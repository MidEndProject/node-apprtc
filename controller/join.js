var Config = require('../config');
var Common = require('./common');
var Rooms = require('../data/rooms');

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


exports.main = {
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
