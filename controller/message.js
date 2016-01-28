var Url = require('url');
var Config = require('../config');
var Common = require('./common');
var Rooms = require('../data/rooms');

var saveMessageFromClient = function (host, roomId, clientId, message, callback) {
  var text = message;
  var key = Common.getCacheKeyForRoom(host, roomId);
  var rooms = Rooms;

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
    } else if (room.getOccupancy() > 5) {
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
  var postRequest = https.request(postOptions, function (result) {
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

exports.main = {
  handler: function (request, reply) {
    var roomId = request.params.roomId;
    var clientId = request.params.clientId;
    var message = request.body;

    saveMessageFromClient(request.headers['host'], roomId, clientId, message, function (error, result) {
      if (error) {
        reply({
          result: error
        });

        return;
      }

      if (result) {
        reply({
          result: 'SUCCESS'
        });
      } else {
        sendMessageToCollider(request, roomId, clientId, message, function (error, result) {
          if (error) {
            reply('').code(500);
          }

          if (result) {
            reply(result);
          }
        });
      }
    });
  }
};
