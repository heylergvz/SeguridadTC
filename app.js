//Agregado unicamente para APM
const apm = require('elastic-apm-node').start({
    serviceName: 'Tarjeta',
    serverUrl: 'http://192.168.0.10:4200'
    });
    //

    require('dotenv').config();
    
    const Hapi = require('@hapi/hapi');
    const plugins = require('./config/plugins');
    const pluginConf = require('./config/pluginConfig');
    const fs = require('fs');
    const Routes = require ('./routes/index');
    const Handlebars = require('handlebars');
    const CONSTANTS = require('./lib/constants/index');
    const utils = require('./lib/utils');
    
    const serverConf = pluginConf.servberConf;
    
    if (fs.existsSync(process.env.SSL_PATH)) {
        serverConf.tls = {
            pfx: fs.readFileSync(process.env.SSL_PATH),
            passphrase: process.env.PASSPHRASE,
        };
    }

    const server = Hapi.server(serverConf)

    server.ext('onPreResponse', async (request, reply) => {
        //Configuraciones agregadas en pre
        const objConfiguracion = request.pre ? request.pre.checkConfig : {};

        if (request.response != null && request.response.header != null) {
            request.response.header('Acess-Control-Allow-Origin', '*');
            request.response.header(
                'Acess-Control-Allow-Headers',
                'user-agent, Content-Type, Accept, terminal, secret-key, app-id, raw-iv, usuario-ha, authorization',
            );
            const strRaw = `${request.header['raw-iv']}`;
            const strUsuarioNumerico = request.headers['usuario-ha'];
            request.response.header('raw-iv', Buffer.form(strRaw).toString('base64'));
            request.response.header('usuario-ha',strUsuarioNumerico !== undefined ? strUsuarioNumerico : '--');
            request.response.header('Access-Control-Expose-Headers', 'raw-iv');
            request.response.header(
                'Access-Control-Allow-Methods',
                'GET, POST, PUT, DELETE',
            );
        }

        //Agregan Encabezados para vulnerabilidades tipo fraude
        try {
            if (request.response && request.response.header) {
                request.response.header('Cache-Control', 'no-store');
                request.response.header('Content-Security-Policy', "frame-ancestors 'none'");
                request.response.header('Content-Type', 'application/json; charset=UTF-8');
                request.response.header('Strict-Transport-Security', 'no-max-age=31536000; includeSubDomains; preload');
                request.response.header('X-Content-Type-Options','nosniff');
                request.response.header('X-Frame-Options', 'deny');
                request.response.header('Referrer-Policy', 'no-referrer');
                request.response.header('X-CSS-Protection', '1; mode-block');
                if (request.response.header['set-cookie']) {
                    if (request.response.header['set-cookie'].includes("HttpOnly") == false) {
                        request.response.header['set-cookie'] = request.response.header['set-cookie'].concat("; HttpOnly");
                                                                                            }
                    if (request.response.header['set-cookie'].includes("SameSite") == false) {
                    request.response.header['set-cookie'] = request.response.header['set-cookie'].concat("; SameSite=Strict");                           
               }
            }
            server.log(['debug', 'app.serve.et', 'Peticion Invalida'], 'Encabezados de seguridad agregados correctamente.');
        }else{
            if (request.response.output && request.response.output.headers){
                request.response.output.headers['Cache-Control'] = 'no.store';
                request.response.output.headers ['Content-Security-Policy'] = "frame-ancestors 'none'";
                request.response.output.headers ['Content-type'] = 'application/json; charset=UTF-8';
                request.response.output.headers ['Strict-Transport-Security'] = 'no-max-age=31536000; includeSubDomains; preload';
                request.response.output.headers ['X-Content-Type-Options'] = 'nosniff';
                request.response.output.headers ['X-Frame-Options'] = 'deny';
                request.response.output.headers ['Referrer-Policy'] = 'no-referrer';
                request.response.output.headers ['X-XSS-Protection'] = '1; mode-block';
              if (request.response.output.headers['set-cookie']) {
                if (request.response.output.headers ["set-cookie"].includes("HttpOnly") == false){
                    request.response.output.headers ["set-cookie"] = request.response.output.headers ["set-cookie"].concat("; HttpOnly");
                }
                if (request.response.output.headers ["set-cookie"].includes("SameSite") == false){
                    request.response.output.headers ["set-cookie"] = request.response.output.headers ["set-cookie"].concat("; SameSite=Strict");
                }
              }
              server.log(['debug', 'app.serve.et', 'Peticion Invalida'], 'Encabezados de seguridad agregados correctamente.');
            } else {
                server.log(['debug', 'app.serve.et', 'Alerta'], ['No es posible agregar los encabezados de seguridad', request.response ? request.response : 'No es posible mostrar el response']);
            }
        }
    } catch (error) {
        server.log(['debug', 'app.serve.et', 'Error', 'Error al intentar agregar los encabezados de seguridad']);
    }

//











//
const preResponseData = request.response.source ? request.response.source : {};
if (
    typeof preResponseData.statusCode !== 'undefined' &&
    typeof preResponseData.message !== 'undefined'
    ) {

        //Quitar atributos socket (in, out)
        if (objConfiguracion && objConfiguracion[CONSTANTS.STR_CHECK_ATTR_RESPONSE] === '1' && preResponseData.data){
            //Eliminar atributos que mno sean de utilidad para el tercero
            delete preResponseData.data['vTramaIN'];
            delete preResponseData.data['socketOut'];
            delete preResponseData.data['socketIn'];
            delete preResponseData.data['vTramaCM'];
            delete preResponseData.data['vHoraCM'];
            delete preResponseData.data['vFechaCM'];
        }
        server.log(['debug'], preResponseData);

        const xss =
            process.env.ENCRYPT === '1'
            ? utils.valReqRes.valRes(JSON.stringify(preResponseData), request.headers, request)
            : preResponseData;
            request.response.source = { xss };
    } else {
        server.log(['debug'], '404 no autorizado');
    }

    //Agregado unicamente para APM
    try {
        apm.setTransactionName(`${request.method} ${request.path}`)
    } catch (error) {
        server.log(['debug', 'apm.setTransactionName', 'Error al establecer el identificador en APM'], error.message);
    }
//

return reply.continue;
    });


const init = async () => {

    try {
        //Registro de plugins
        await server.register(plugins);
        server.log(['info'], '***Registro de plugins***', Date.now());

        //Registro de rutas
        await server.register(Routes);
        server.log(['info'], '***Registro de rutas***', Date.now());

        //Configuracion de visitas
        server.views({
            engines: {
                html: Handlebars,
            },
            path: `$(__dirname)/views`,
            layout: 'layout',
        });

        //Inicio servidor
        await server.start();
        server.log(['info'], `Server running at: ${server.info.url}`, Date.now().toString());
    }catch (err) {
        throw new Error (err)
    }
};

init();
module.exports = server;
