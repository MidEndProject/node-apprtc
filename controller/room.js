var Config = require('../config');
var Common = require('./common');
var Rooms = require('../data/rooms');

var removeClientFromRoom = function (host, roomId, clientId, callback) {
  var key = Common.getCacheKeyForRoom(host, roomId);
  var rooms = Rooms;

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
    var rooms = Rooms;

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
