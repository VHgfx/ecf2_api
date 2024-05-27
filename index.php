<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Slim\Middleware\BodyParsingMiddleware;

use Slim\Factory\AppFactory;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require_once __DIR__ . '/vendor/autoload.php';
$app = AppFactory::create();
$app->addBodyParsingMiddleware();

$key = 'ïOÖbÈ3~_Äijb¥d-ýÇ£Hf¿@xyLcP÷@';

$authMiddleware = function($request,$handler)use ($key){
    $authMiddleware = $request->getHeader('Authorization');
    if(!empty($authMiddleware)){
        $token = $authMiddleware[0];
        $decoded = JWT::decode($token, new Key($key, 'HS256'));
        $request = $request->withAttribute('id',$decoded->id);
          return $response = $handler->handle($request);
        }else{
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode(['erreur' => 'token vide ou invalide']));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }
};


$app->post('/addUser', function (Request $request, Response $response) {
    $err = array();
    require_once 'db.php';
    $data = $request->getParsedBody();


    if(empty($data['lastname'])){
    $err['lastname'] = 'nom de famille vide';
    }
    if(empty($data['firstname'])){
        $err['firstname'] = 'prénom vide';
    }
    if(empty($data['email'])){
        $err['email'] = 'adresse email vide';
    }
    if(empty($data['password'])){
        $err['password'] = 'mot de passe vide';
    }

    if(empty($err)){

        $passwordhash = password_hash($data['password'],PASSWORD_DEFAULT);
        $query = 'INSERT INTO `users` (`firstname`,`lastname`,`email`,`password`) VALUES(?,?,?,?)';
        $queryexec = $database->prepare($query);
        $queryexec->bindValue(1, $data['firstname'] ,PDO::PARAM_STR);
        $queryexec->bindValue(2, $data['lastname'] ,PDO::PARAM_STR);
        $queryexec->bindValue(3, $data['email'] ,PDO::PARAM_STR);
        $queryexec->bindValue(4, $passwordhash ,PDO::PARAM_STR);
        $queryexec->execute();

        $response->getBody()->write(json_encode(['valid' => 'ok']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);



    }else{
    $response->getBody()->write(json_encode(['erreur' => $err]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

});


$app->post('/login', function (Request $request, Response $response)use ($key) {
    $data = $request->getParsedBody();
    require_once 'db.php';
    $query = 'SELECT `id`,`password` FROM `users` WHERE `email` = ?';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(1, $data['email'] ,PDO::PARAM_STR);
    $queryexec->execute();
    $res = $queryexec->fetchAll();
    if(password_verify($data['password'],$res[0]['password'])){

        $payload = [
            'iat' => time(),
            'exp' => time() + 1800,
            'id' => $res[0]['id']
        ];

        $jwt = JWT::encode($payload, $key, 'HS256');
        $response->getBody()->write(json_encode(['valid' => 'Vous etes connecté', 'token' => $jwt]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);

    }else{
        $response->getBody()->write(json_encode(['erreur' => 'mauvais mot de passe ou mauvais mail']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
});

$app->get('/profil', function (Request $request, Response $response) {
    require_once 'db.php';
    $id = $request->getAttribute('id');
    $query = 'SELECT * FROM `users` WHERE `id` = ?';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(1, $id ,PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetchAll();
    $response->getBody()->write(json_encode(['profil valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
})->add($authMiddleware);

$app->get('/addManga', function (Request $request, Response $response) {
    require_once 'db.php';
    $id = $request->getAttribute('id');
    $query = 'SELECT * FROM `users` WHERE `id` = ?';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(1, $id ,PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetchAll();
    $response->getBody()->write(json_encode(['profil valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
})->add($authMiddleware);

$app->run();
