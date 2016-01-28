var Index = require('../controller');
var Join = require('../controller/join');
var Message = require('../controller/message');
var Room = require('../controller/room');

exports.endpoints = [
  { method: 'GET', path: '/', config: Index.main },
  { method: 'POST', path: '/join/{roomId}', config: Join.main },
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
