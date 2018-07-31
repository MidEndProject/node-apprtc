var Https = require('https');
var Common = require('./common');

exports.main = {
  handler: function (request, reply) {
    var params = Common.getRoomParameters(request, null, null, null);

    reply.view('index_template', params);
  }
};

exports.turn = {
  handler: function (request, reply) {
    var getOptions = {
      host: 'instant.io',
      port: 443,
      path: '/__rtcConfig__',
      method: 'GET'
    };
    Https.get(getOptions, function (result) {
      console.log(result.statusCode == 200);

      var body = '';

      result.on('data', function (data) {
        body += data;
      });
      result.on('end', function () {
        reply(body);
      });
    }).on('error', function (e) {
      reply({
        "username":"webrtc",
        "password":"webrtc",
        "uris":[
          "stun:stun.l.google.com:19302",
          "stun:stun1.l.google.com:19302",
          "stun:stun2.l.google.com:19302",
          "stun:stun3.l.google.com:19302",
          "stun:stun4.l.google.com:19302",
          "stun:stun.services.mozilla.com",
          "turn:turn.anyfirewall.com:443?transport=tcp"
        ]
      });
    });
  }
};
