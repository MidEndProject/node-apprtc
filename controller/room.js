var Config = require('../config');
var Common = require('./common');
var Rooms = require('../data/rooms');

var rooms = new Rooms();

var addClientToRoom = function (request, roomId, clientId, isLoopback, callback) {
  var key = Common.getCacheKeyForRoom(request.headers.host, roomId);
  var rooms = new Rooms();

  rooms.createIfNotExist(key, function (error, room) {
    if (error) {
      callback(error);

      return;
    }

    var error = null;
    var isInitiator = false;
    var messages = [];
    var roomState = '';
    var occupancy = room.getOccupancy();

    if (occupancy >= 5) {
      error = Config.constant.RESPONSE_ROOM_FULL;
      callback(error, {
        messages: messages
      });

      return;
    } else if (room.hasClient(clientId)) {
      error = Config.constant.RESPONSE_DUPLICATE_CLIENT;
      callback(error, {
        messages: messages
      });

      return;
    } else {
      room.join(clientId, function (error, client, otherClient) {
        if (error) {
          callback(error, {
            messages: messages
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
}

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

        if (room.getOccupancy() >= 5) {
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

    addClientToRoom(request, roomId, clientId, isLoopback, function(error, result) {
      if (error) {
        console.error('Error adding client to room: ' + error + ', room_state=' + result.room_state);
        reply({
          result: error,
          params: result
        });

        return;
      }

      var params = Common.getRoomParameters(request, roomId, clientId, result.is_initiator);
      params.messages = result.messages;

      reply({
        result: 'SUCCESS',
        params: params
      });

      console.log('User ' + clientId + ' joined room ' + roomId);
      console.log('Room ' + roomId + ' has state ' + result.room_state);
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

      reply('');
    });
  }
};
