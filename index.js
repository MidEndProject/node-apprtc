var Hapi = require('hapi');
var Route = require('./route');
var Config = require('./config');

var app = {};
app.config = Config;

var server = new Hapi.Server();

server.connection({ routes: { cors: true }, port: app.config.server.port });

server.register(require('inert'));
server.register(require('vision'), function (error) {
  if (error) {
    console.log('Failed to load vision.');
  }
});

server.route(Route.endpoints);

server.views({
  engines: {
    html: require('handlebars')
  },
  relativeTo: __dirname,
  path: './view'
});

server.start(function() {
  console.log('Server started at ' + server.info.uri + '.');
});
