var Url = require('url');
var Http = require('http');
var Https = require('https');
var Config = require('../config');
var Common = require('./common');
var Rooms = require('../data/rooms');

var rooms = new Rooms();

var addClientToRoom = function (request, roomId, clientId, isLoopback, callback) {
  var key = Common.getCacheKeyForRoom(request.headers.host, roomId);

  rooms.createIfNotExist(key, function (error, room) {
    var error = null;
    var isInitiator = false;
    var messages = [];
    var occupancy = room.getOccupancy();

    if (occupancy >= 2) {
      error = Config.constant.RESPONSE_ROOM_FULL;
      callback(error, {
        messages: messages,
        room_state: room.toString()
      });

      return;
    } else if (room.hasClient(clientId)) {
      error = Config.constant.RESPONSE_DUPLICATE_CLIENT;
      callback(error, {
        messages: messages,
        room_state: room.toString()
      });

      return;
    } else {
      room.join(clientId, function (error, client, otherClient) {
        if (error) {
          callback(error, {
            messages: messages,
            room_state: null
          });

          return;
        }

        if (client.isInitiator && isLoopback) {
          room.join(Config.constant.LOOPBACK_CLIENT_ID);
        }

        var messages = otherClient ? otherClient.messages : messages;

        if (otherClient) otherClient.clearMessages();

        console.log('Added client ' + clientId + ' in room ' + roomId);
        callback(null, {
          is_initiator: client.isInitiator,
          messages: messages,
          room_state: room.toString()
        });
      });
    }
  });
};

var saveMessageFromClient = function (host, roomId, clientId, message, callback) {
  var text = message;
  var key = Common.getCacheKeyForRoom(host, roomId);

  rooms.get(key, function (error, room) {
    if (!room) {
      console.warn('Unknown room: ' + roomId);
      callback({
        error: Config.constant.RESPONSE_UNKNOWN_ROOM
      });

      return;
    } else if (!room.hasClient(clientId)) {
      console.warn('Unknown client: ' + clientId);
      callback({
        error: Config.constant.RESPONSE_UNKNOWN_CLIENT
      });

      return;
    } else if (room.getOccupancy() > 1) {
      callback(null, false);
    } else {
      var client = room.getClient(clientId);
      client.addMessage(text);
      console.log('Saved message for client ' + clientId + ':' + client.toString() + ' in room ' + roomId);
      callback(null, true);

      return;
    }
  });
};

var sendMessageToCollider = function (request, roomId, clientId, message, callback) {
  console.log('Forwarding message to collider from room ' + roomId + ' client ' + clientId);
  var wssParams = Common.getWSSParameters(request);
  var wssHost = Url.parse(wssParams.wssPostUrl);
  var postOptions = {
    host: wssHost.hostname,
    port: wssHost.port,
    path: '/' + roomId + '/' + clientId,
    method: 'POST'
  };
  var postRequest = Https.request(postOptions, function (result) {
    if (result.statusCode == 200) {
      callback(null, {
        result: 'SUCCESS'
      });

      return;
    } else {
      console.error('Failed to send message to collider: ' + result.statusCode);
      callback(result.statusCode);

      return;
    }
  });

  postRequest.write(message);
  postRequest.end();
};

var removeClientFromRoom = function (host, roomId, clientId, callback) {
  var key = Common.getCacheKeyForRoom(host, roomId);

  rooms.get(key, function (error, room) {
    if (!room) {
      console.warn('remove_client_from_room: Unknown room: ' + roomId);
      callback(Config.constant.RESPONSE_UNKNOWN_ROOM, {
        room_state: null
      });

      return;
    } else if (!room.hasClient(clientId)) {
      console.warn('remove_client_from_room: Unknown client: ' + clientId);
      callback(Config.constant.RESPONSE_UNKNOWN_CLIENT, {
        room_state: null
      });

      return;
    } else {
      room.removeClient(clientId, function (error, isRemoved, otherClient) {
        if (room.hasClient(Config.constant.LOOPBACK_CLIENT_ID)) {
          room.removeClient(Config.constant.LOOPBACK_CLIENT_ID, function (error, isRemoved) {
            return;
          });
        } else {
          if (otherClient) {
            otherClient.isInitiator = true;
          }
        }

        callback(null, {
          room_state: room.toString()
        });
      });
    }
  });
};

exports.main = {
  handler: function (request, reply) {
    var roomId = request.params.roomId;
    var key = Common.getCacheKeyForRoom(request.headers['host'], roomId);

    rooms.get(key, function (error, room) {
      if (room) {
        console.log('Room ' + roomId + ' has state ' + room.toString());

        if (room.getOccupancy() >= 2) {
          console.log('Room ' + roomId + ' is full');
          reply.view('full_template', {});

          return;
        }
      }

      var params = Common.getRoomParameters(request, roomId, null, null);
      reply.view('index_template', params);
    });
  }
};

exports.join = {
  handler: function (request, reply) {
    var roomId = request.params.roomId;
    var clientId = Common.generateRandom(8);
    var isLoopback = request.params.debug == 'loopback';
    var response = null;

    addClientToRoom(request, roomId, clientId, isLoopback, function(error, result) {
      if (error) {
        console.error('Error adding client to room: ' + error + ', room_state=' + result.room_state);
        response = {
          result: error,
          params: result
        };
        reply(JSON.stringify(response));

        return;
      }

      var params = Common.getRoomParameters(request, roomId, clientId, result.is_initiator);
      params.messages = result.messages;
      response = {
        result: 'SUCCESS',
        params: params
      };
      reply(JSON.stringify(response));

      console.log('User ' + clientId + ' joined room ' + roomId);
      console.log('Room ' + roomId + ' has state ' + result.room_state);
    });
  }
};

exports.message = {
  handler: function (request, reply) {
    var userAgent = request.headers['user-agent'];
    var roomId = request.params.roomId;
    var clientId = request.params.clientId;
    var message = null;
    var response = null;

    console.log('User ' + clientId + ' - ' + userAgent);
    if (userAgent.indexOf('CFNetwork') > -1) {
      var malformed_sdp = request.payload;
      var keys = Object.keys(malformed_sdp);
      var key = keys[0];
      var value = malformed_sdp[key];
      var sdp = key + '=' + value;
      message = sdp;

      if (message.slice(-1) == '=') {
         message = message.slice(0, -1);
      }
    } else {
      message = request.payload;
    }

    saveMessageFromClient(request.headers['host'], roomId, clientId, message, function (error, result) {
      if (error) {
        response = {
          result: error
        };
        reply(JSON.stringify(response));

        return;
      }

      if (result) {
        response = {
          result: 'SUCCESS'
        };
        reply(JSON.stringify(response));
      } else {
        sendMessageToCollider(request, roomId, clientId, message, function (error, result) {
          if (error) {
            reply('').code(500);
          }

          if (result) {
            reply(JSON.stringify(result));
          }
        });
      }
    });
  }
};

exports.leave = {
  handler: function (request, reply) {
    var roomId = request.params.roomId;
    var clientId = request.params.clientId;

    removeClientFromRoom(request.headers['host'], roomId, clientId, function (error, result) {
      if (error) {
        console.log('Room ' + roomId + ' has state ' + result.room_state);
      }

      console.log('Room ' + roomId + ' has state ' + result.room_state);
      reply('');
    });
  }
};
