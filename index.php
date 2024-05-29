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
        $response->getBody()->write(json_encode(['erreur' => "Le nom est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    if(empty($data['firstname'])){
        $response->getBody()->write(json_encode(['erreur' => "Le prénom est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    
    if(empty($data['password'])){
        $response->getBody()->write(json_encode(['erreur' => "Le mot de passe est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }

    
    if(empty($data['email'])){
        $response->getBody()->write(json_encode(['erreur' => "L'email est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    } else { // Check si mail déjà utilisé
        $existingQuery = "SELECT * FROM users WHERE email = :email";
        
        $stmt = $database->prepare($existingQuery);
        $stmt->bindValue(":email", $data['email'], PDO::PARAM_STR);
        $stmt->execute();

        $count = $stmt->fetchColumn();
        if($count >= 1){   
            $response->getBody()->write(json_encode(['erreur' => "L'email est déjà utilisé"]));
            return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
        }
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

        $response->getBody()->write(json_encode(['valid' => 'Inscription réussie !']));
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


$app->get('/getTokenExp', function (Request $request, Response $response) use ($key) {
    require_once 'db.php';
    $token = $request->getHeader('Authorization')[0];
    $secretKey = "ïOÖbÈ3~_Äijb¥d-ýÇ£Hf¿@xyLcP÷@";

    try {
        // Decode the token using the secret key
        $decoded = JWT::decode($token, new Key($secretKey, 'HS256'));
        $expiration = $decoded->exp;

        // Send the expiration time in the response
        $response->getBody()->write(json_encode(['exp' => $expiration]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } catch (Exception $e) {
        // Handle token decoding errors
        $response->getBody()->write(json_encode(['error' => 'Invalid token']));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(401);
    }
})->add($authMiddleware);


// Ajout : 1 manga
$app->post('/manga/add', function (Request $request, Response $response) {
    require_once 'db.php';
    $data = $request->getParsedBody();


    if(empty($data['titre'])){
    $response->getBody()->write(json_encode(['erreur' => "Le titre est vide"]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    if(empty($data['auteur'])){
        $response->getBody()->write(json_encode(['erreur' => "L'auteur est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    if(empty($data['id_categories'])){
        $response->getBody()->write(json_encode(['erreur' => "La catégorie est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
    }
    if(empty($data['resume'])){
        $response->getBody()->write(json_encode(['erreur' => "Le résumé est vide"]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(400);
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

    }
});

// Récupération : Liste de tous les mangas
$app->get('/manga/all', function (Request $request, Response $response) {
    require_once 'db.php';
    
    $query = 'SELECT mangas.*,
                IFNULL(suivi_counts.suivi_count, 0) AS suivi_count
                FROM mangas
                LEFT JOIN (
                SELECT mangas_id, COUNT(*) AS suivi_count
                FROM issuivi
                GROUP BY mangas_id
                ) AS suivi_counts ON mangas.id = suivi_counts.mangas_id;';
    $queryexec = $database->prepare($query);
    $queryexec->execute();
    $res = $queryexec->fetchAll(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});

// Récupération : Liste de toutes les catégories
$app->get('/manga/categories', function (Request $request, Response $response) {
    require_once 'db.php';
    
    $query = 'SELECT * FROM `categories`';
    $queryexec = $database->prepare($query);
    $queryexec->execute();
    $res = $queryexec->fetchAll(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'ok', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});


// Récupération : Détails 1 manga (infos + compte des suivis)
$app->get('/manga/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';

    $selectedManga = $param['manga_id'];
    
    $query = 'SELECT mangas.*, categories.nom_categorie, (SELECT COUNT(*) FROM issuivi WHERE issuivi.mangas_id = :id) AS suivi_count
    FROM `mangas` 
    JOIN categories ON mangas.id_categories = categories.id
    LEFT JOIN issuivi ON mangas.id = issuivi.mangas_id
    WHERE mangas.id = :id';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':id', $selectedManga, PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetch(PDO::FETCH_ASSOC);
    $response->getBody()->write(json_encode(['valid' => 'Infos du manga récupérées', 'data' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
});

// Suppression : 1 manga
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

// Ajout : Suivi pour 1 manga pour 1 user
$app->post('/suivi/add/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';
    $data = $request->getParsedBody();
    $id = $request->getAttribute('id');

    $mangas_id = $param['manga_id'];
    
    $query = 'INSERT INTO `issuivi` (`mangas_id`,`users_id`) VALUES (:mangas_id, :users_id)';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':mangas_id', $mangas_id, PDO::PARAM_INT);
    $queryexec->bindValue(':users_id', $id, PDO::PARAM_INT);
    $queryexec->execute();

    $response->getBody()->write(json_encode(['valid' => 'Manga suivi']));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(201);
})->add($authMiddleware);

// Récupérer : Si 1 manga suivi par 1 user
$app->get('/suivi/get/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';
    $data = $request->getParsedBody();
    $id = $request->getAttribute('id');
    $mangas_id = $param['manga_id'];

    $existingQuery = "SELECT * FROM issuivi WHERE mangas_id = :mangas_id AND users_id = :users_id";
    $queryexec = $database->prepare($existingQuery);
    $queryexec->bindValue(':mangas_id', $mangas_id, PDO::PARAM_INT);
    $queryexec->bindValue(':users_id', $id, PDO::PARAM_INT);
    $queryexec->execute();

    $count = $queryexec->fetchColumn();
    if($count >= 1){   
        $response->getBody()->write(json_encode(['valid' => true]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    } else {
        $response->getBody()->write(json_encode(['valid' => false]));
        return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
    }
})->add($authMiddleware);

// Delete : Suivi pour 1 manga pour 1 personne
$app->delete('/suivi/remove/{manga_id}', function (Request $request, Response $response, $param) {
    require_once 'db.php';
    $data = $request->getParsedBody();
    $id = $request->getAttribute('id');

    $mangas_id = $param['manga_id'];
    
    $query = 'DELETE FROM `issuivi` WHERE mangas_id = :mangas_id AND users_id = :users_id';
    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':mangas_id', $mangas_id, PDO::PARAM_INT);
    $queryexec->bindValue(':users_id', $id, PDO::PARAM_INT);
    $queryexec->execute();

    $response->getBody()->write(json_encode(['valid' => 'Manga non suivi']));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
})->add($authMiddleware);

// Récupération : Liste des mangas suivis pour 1 user
$app->get('/suivi/liste', function (Request $request, Response $response) {
    require_once 'db.php';
    $id = $request->getAttribute('id');

    $query = 'SELECT mangas.*, (SELECT COUNT(*) FROM issuivi WHERE issuivi.users_id = :users_id) AS total_count
            FROM `issuivi` 
            LEFT JOIN mangas ON mangas.id = issuivi.mangas_id
            WHERE issuivi.users_id = :users_id';

    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':users_id', $id, PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode(['valid' => $res]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
})->add($authMiddleware);

// Récupération : Nombre mangas suivis pour 1 personne
$app->get('/suivi/statUser', function (Request $request, Response $response) {
    require_once 'db.php';
    $id = $request->getAttribute('id');

    $query = 'SELECT COUNT(*) AS total_count
            FROM `issuivi` 
            LEFT JOIN mangas ON mangas.id = issuivi.mangas_id
            WHERE issuivi.users_id = :users_id';

    $queryexec = $database->prepare($query);
    $queryexec->bindValue(':users_id', $id, PDO::PARAM_INT);
    $queryexec->execute();
    $res = $queryexec->fetch(PDO::FETCH_ASSOC);

    $totalCount = $res['total_count'];

    $response->getBody()->write(json_encode(['valid' => $totalCount]));
    return $response->withHeader('Content-Type', 'application/json')->withStatus(200);
})->add($authMiddleware);

$app->run();