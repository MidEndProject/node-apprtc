var Common = require('./common');

exports.main = {
  handler: function (request, reply) {
    var params = Common.getRoomParameters(request, null, null, null);

    return reply.view('index_template', params);
  }
};
