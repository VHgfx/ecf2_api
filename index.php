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


// Ajout manga
$app->post('/manga/add', function (Request $request, Response $response) {
    $err = array();
    require_once 'db.php';
    $data = $request->getParsedBody();


    if(empty($data['titre'])){
    $err['titre'] = 'titre vide';
    }
    if(empty($data['auteur'])){
        $err['auteur'] = 'auteur vide';
    }
    if(empty($data['id_categories'])){
        $err['id_categories'] = 'id_categorie vide';
    }
    if(empty($data['resume'])){
        $err['resume'] = 'résumé vide';
    }

    if(empty($err)){

        
        $query = 'INSERT INTO `mangas` (`titre`,`auteur`,`id_categories`,`resume`) VALUES(?,?,?,?)';
        $queryexec = $database->prepare($query);
        $queryexec->bindValue(1, $data['titre'] ,PDO::PARAM_STR);
        $queryexec->bindValue(2, $data['auteur'] ,PDO::PARAM_STR);
        $queryexec->bindValue(3, $data['id_categories'] ,PDO::PARAM_INT);
        $queryexec->bindValue(4, $data['resume'] ,PDO::PARAM_STR);
        $queryexec->execute();

        $response->getBody()->write(json_encode(['valid' => 'manga inséré']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(201);

    }else{
    $response->getBody()->write(json_encode(['erreur' => $err]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

});

// Liste de tous les mangas
$app->get('/manga/all', function (Request $request, Response $response) {
    require_once 'db.php';
    
    $query = 'SELECT * FROM `mangas`';
    $queryexec = $database->prepare($query);
    $queryexec->execute();
    $res = $queryexec->fetchAll(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});

// Liste de toutes les catégories
$app->get('/manga/categories', function (Request $request, Response $response) {
    require_once 'db.php';
    
    $query = 'SELECT * FROM `categories`';
    $queryexec = $database->prepare($query);
    $queryexec->execute();
    $res = $queryexec->fetchAll(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});


// Détails 1 manga
$app->get('/manga/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';

    $selectedManga = $param['manga_id'];
    
    $query = 'SELECT mangas.*, categories.nom_categorie
    FROM `mangas` 
    JOIN categories ON mangas.id_categories = categories.id
    WHERE mangas.id = :id';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':id', $selectedManga, PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetch(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'Infos du manga récupérées', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});

// Liste de tous les mangas
$app->delete('/manga/delete/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';

    $selectedManga = $param['manga_id'];
    
    $query = 'DELETE FROM `mangas` WHERE id = :id';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':id', $selectedManga, PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetchAll();
    $response->getBody()->write(json_encode(['valid' => 'Manga supprimé']));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});


$app->run();