var Url = require('url');
var Util = require('util');
var Querystring = require('querystring');
var Config = require('../config');

var getHdDefault = function (userAgent) {
  if (typeof userAgent !== 'undefined') {
    if (userAgent.indexOf('Android') > -1 || userAgent.indexOf('Chrome') == -1) {
      return false;
    }
  }

  return true;
};

var makePcConfig = function (iceTransports) {
  var pcConfig = {
    iceServers: [],
    bundlePolicy: 'max-bundle',
    rtcpMuxPolicy: 'require'
  };

  if (iceTransports) {
    pcConfig.iceTransports = iceTransports;
  }

  return pcConfig;
};

var maybeAddConstraint = function (constraints, param, constraint) {
  var object = {};

  if (param && param.toLowerCase() == 'true') {
    object[constraint] = true;
    constraints['optional'].push(object);
  } else if (param && param.toLowerCase() == 'false') {
    object[constraint] = false;
    constraints['optional'].push(object);
  }

  return constraints;
};

var makePcConstraints = function (dtls, dscp, ipv6) {
  var constraints = { optional: [] };
  maybeAddConstraint(constraints, dtls, 'DtlsSrtpKeyAgreement');
  maybeAddConstraint(constraints, dscp, 'googDscp');
  maybeAddConstraint(constraints, ipv6, 'googIPv6');

  return constraints;
};

function addMediaTrackConstraint(trackConstraints, constraintString) {
  var tokens = constraintString.split(':');
  var mandatory = true;

  if (tokens.length == 2) {
    mandatory = (tokens[0] == 'mandatory');
  } else {
    mandatory = !tokens[0].indexOf('goog') == 0;
  }

  tokens = tokens[tokens.length-1].split('=');

  if (tokens.length == 2) {
    if (mandatory) {
      trackConstraints.mandatory[tokens[0]] = tokens[1];
    } else {
      var object = {};
      object[tokens[0]] = tokens[1];
      trackConstraints.optional.push(object);
    }
  } else {
    console.error('Ignoring malformed constraint: ' + constraintString);
  }
};

var makeMediaTrackConstraints = function (constraintsString) {
  var trackConstraints;

  if (!constraintsString || constraintsString.toLowerCase() == 'true') {
    trackConstraints = true;
  } else if (constraintsString.toLowerCase() == 'false') {
    trackConstraints = false;
  } else {
    trackConstraints = { mandatory: {}, optional: [] };
    var constraintsArray = constraintsString.split(',');

    for (var i in constraintsArray) {
      var constraintString = constraintsArray[i];
      addMediaTrackConstraint(trackConstraints, constraintString);
    }
  }

  return trackConstraints;
};

var makeMediaStreamConstraints = function (audio, video, firefoxFakeDevice) {
  var streamConstraints = {
    audio: makeMediaTrackConstraints(audio),
    video: makeMediaTrackConstraints(video)
  };

  if (firefoxFakeDevice) streamConstraints.fake = true;

  console.log('Applying media constraints: ' + JSON.stringify(streamConstraints))

  return streamConstraints;
};

var getWSSParameters = function (request) {
  var wssHostPortPair = request.params.wshpp;
  var wssTLS = request.query.wstls;

  if (!wssHostPortPair) {
    wssHostPortPair = Config.constant.WSS_HOST_PORT_PAIRS[0];
  }

  if (wssTLS && wssTLS == 'false') {
    return {
      wssUrl: 'ws://' + wssHostPortPair + '/ws',
      wssPostUrl: 'http://' + wssHostPortPair
    }
  } else {
    return {
      wssUrl: 'wss://' + wssHostPortPair + '/ws',
      wssPostUrl: 'https://' + wssHostPortPair
    }
  }
};

var getVersionInfo = function () {
  return null;
};

var generateRandom = function (length) {
  var word = '';

  for (var i = 0; i < length; i++) {
    word += Math.floor((Math.random() * 10));
  }

  return word;
};

exports.getRoomParameters = function (request, roomId, clientId, isInitiator) {
  var errorMessages = [];
  var warningMessages = [];

  var userAgent = request.headers['user-agent'];
  var responseType = request.params.t;
  var iceTransports = request.params.it;
  var turnTransports = request.params.tt;
  var turnBaseUrl = request.params.ts || Config.constant.TURN_BASE_URL;

  var audio = request.params.audio;
  var video = request.params.video;
  var firefoxFakeDevice = request.params.firefox_fake_device;
  var hd = request.params.hd ? request.params.hd.toLowerCase() : null;

  if (video && hd) {
    var message = 'The "hd" parameter has overridden video=' + video;
    errorMessages.push(message);
    console.log(message);
  }

  if (hd == 'true') {
    video = 'mandatory:minWidth=1280,mandatory:minHeight=720';
  } else if (!video && !hd && getHdDefault(userAgent)) {
    video = 'optional:minWidth=1280,optional:minHeight=720';
  }

  if (request.params.minre || request.params.maxre) {
    var message = 'The "minre" and "maxre" parameters are no longer supported. Use "video" instead.';
    errorMessages.push(message);
    console.error(message);
  }

  var dtls = request.params.dtls;
  var dscp = request.params.dscp;
  var ipv6 = request.params.ipv6;

  var debug = request.params.debug;

  if (debug == 'loopback') {
    var includeLoopbackJS = '<script src="/js/loopback.js"></script>';
    dtls = 'false';
  } else {
    var includeLoopbackJS = '';
  }

  var username = clientId ? clientId : generateRandom(9);
  var turnUrl = turnBaseUrl.length > 0 ? Util.format(Config.constant.TURN_URL_TEMPLATE, turnBaseUrl) : null;

  var pcConfig = makePcConfig(iceTransports);
  var pcConstraints = makePcConstraints(dtls, dscp, ipv6);
  var offerOptions = {};
  var mediaConstraints = makeMediaStreamConstraints(audio, video, firefoxFakeDevice);

  var wssParams = getWSSParameters(request);
  var wssUrl = wssParams.wssUrl;
  var wssPostUrl = wssParams.wssPostUrl;

  var bypassJoinConfirmation = false;

  var params = {
    'error_messages': errorMessages,
    'warning_messages': warningMessages,
    'is_loopback' : JSON.stringify(debug == 'loopback'),
    'pc_config': JSON.stringify(pcConfig),
    'pc_constraints': JSON.stringify(pcConstraints),
    'offer_options': JSON.stringify(offerOptions),
    'media_constraints': JSON.stringify(mediaConstraints),
    'turn_url': turnUrl,
    'turn_transports': turnTransports,
    'include_loopback_js' : includeLoopbackJS,
    'wss_url': wssUrl,
    'wss_post_url': wssPostUrl,
    'bypass_join_confirmation': JSON.stringify(bypassJoinConfirmation),
    'version_info': JSON.stringify(getVersionInfo())
  };

  var protocol = request.headers['x-forwarded-proto'];

  if (request.headers['origin']) {
    protocol = protocol || Url.parse(request.headers['origin']).protocol || 'http:';
  }

  if (roomId) {
    params['room_id'] = roomId;
    params['room_link'] =  protocol + '//' + request.headers['host'] + '/r/' + roomId;
  }

  if (clientId) {
    params['client_id'] = clientId;
  }

  if (typeof isInitiator === 'boolean') {
    params['is_initiator'] = JSON.stringify(isInitiator);
  }

  return params;
};

exports.getCacheKeyForRoom = function (host, roomId) {
  return host + '/' + roomId;
};

exports.generateRandom = generateRandom;
exports.getWSSParameters = getWSSParameters;
