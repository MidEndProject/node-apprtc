var Index = require('../controller');
var Message = require('../controller/message');
var Room = require('../controller/room');

exports.endpoints = [
  { method: 'GET', path: '/', config: Index.main },
  { method: 'POST', path: '/join/{roomId}', config: Room.join },
  { method: 'POST', path: '/message/{roomId}/{clientId}', config: Message.main },
  { method: 'GET', path: '/r/{roomId}', config: Room.main },
  { method: 'POST', path: '/leave/{roomId}/{clientId}', config: Room.leave },
  { method: 'GET', path: '/{param*}', handler: {
      directory: {
        path: 'public',
        listing: false
      }
    }
  }
];
