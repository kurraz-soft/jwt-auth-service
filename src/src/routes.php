<?php

use Slim\Http\Request;
use Slim\Http\Response;

$settings = $app->getContainer()->get('settings');

$db = new mysqli($settings['db']['host'],$settings['db']['username'],$settings['db']['password'],$settings['db']['database']);

// Routes

$app->add(function(Request $request, Response $response, callable $next){
    return $next($request, $response->withHeader('Access-Control-Allow-Origin','*'));
});

$app->get('/test',function (){
    phpinfo();
});

/*$app->options('/api/[{method:.*}]', function(Request $request, Response $response, array $args){

    return $response
        ->withHeader('Access-Control-Allow-Headers', 'content-type, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
});*/

$key = 'secret';

$app->get('/api/auth/v1/auth', function (Request $request, Response $response, array $args) use ($key){

    $jwt = explode('Bearer ',$request->getHeader('Authorization')[0])[1];

    $ret = checkAuth($request, $response, $key);

    if($ret === true)
        return $response->withJson([
                'status' => 'ok',
                'token' => $jwt,
            ]);
    else return $ret;
});

$app->get('/api/auth/v1/login', function (Request $request, Response $response, array $args) use ($key, $db){

    if(!$request->getParam('login') || !$request->getParam('password'))
        return $response->withStatus(401);

    $login = $request->getParam('login');
    $password = $request->getParam('password');

    $q = $db->prepare('SELECT * FROM users WHERE username=?');
    $q->bind_param('s', $login);
    $q->execute();
    $res = $q->get_result();
    if(!$res) return $response->withStatus(401);
    $res = $res->fetch_assoc();
    if(!$res) return $response->withStatus(401);
    if(!password_verify($password, $res['password_hash'])) return $response->withStatus(401);

    $payload = [
        'exp' => time() + 3600,
        'username' => $login,
    ];

    $jwt = JWT::encode($payload, $key);

    return $response
        ->withJson([
            'status' => 'ok',
            'token' => $jwt,
        ]);
});

$app->post('/api/auth/v1/register', function (Request $request, Response $response, array $args) use ($key, $app, $db) {

    $login = $request->getParam('username');
    $password = $request->getParam('password');

    if(!$login || !$password) return $response->withStatus(400);

    $q = $db->prepare('INSERT INTO users SET username=?, password_hash=?');
    $q->bind_param("ss", $login, password_hash($password,PASSWORD_DEFAULT));
    if($q->execute())
    {
        return $response->withJson([
            'status' => 'ok'
        ]);
    }else return $response->withStatus(400);

});

$app->get('/api/[{method:.*}]', function(Request $request, Response $response, array $args) use ($key){

    $ret = checkAuth($request, $response, $key);
    if($ret !== true) return $ret;

    //TODO load requested API

    return $response;
});

function checkAuth(Request $request, Response $response, $key)
{
    try{

        if(!$request->getHeader('Authorization')) throw new Exception();

        $jwt = explode('Bearer ',$request->getHeader('Authorization')[0])[1];

        $data = (array)JWT::decode($jwt, $key)[1];
        if((int)$data['exp'] < time())
            return $response
                ->withJson([
                    'status' => 'expired',
                    'token' => $jwt,
                    'data' => $data,
                ])->withStatus(401);
        else
            return true;
    }catch (Exception $e)
    {
        $jwt = explode('Bearer ',$request->getHeader('Authorization')[0])[1];
        return $response
            ->withJson(['status' => $e->getMessage(), 'token' => $jwt])
            ->withStatus(401);
    }
}