  <?php
// ----------------------------------------------------
// A. Configuration de la connexion à la BDD (PDO)
// ----------------------------------------------------
$host = 'localhost';
$db   = 'utilisateur'; // IMPORTANT : remplacez par le nom de votre base !
$user = 'root'; 
$pass = '';     // Laissez vide si vous utilisez XAMPP/WAMP par défaut
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false, // Sécurité : Désactiver l'émulation des requêtes préparées
];
try {
     $pdo = new PDO($dsn, $user, $pass, $options);
} catch (\PDOException $e) {
     die("Erreur de connexion à la base de données : " . $e->getMessage());
}

// ----------------------------------------------------
// B. Traitement des données du formulaire (Sécurité)
// ----------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Nettoyage des données
    $nom = htmlspecialchars($_POST['nom'] ?? '');
    $email = filter_var($_POST['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $mdp_clair = $_POST['mot_de_passe'] ?? '';

    // 2. Vérification de base
    if (empty($nom) || empty($email) || empty($mdp_clair)) {
        die("Tous les champs sont requis.");
    }
    
    // 3. Hachage sécurisé du mot de passe
    // C'EST L'ÉTAPE LA PLUS CRUCIALE POUR LA SÉCURITÉ
    $mdp_hache = password_hash($mdp_clair, PASSWORD_DEFAULT);

    // ----------------------------------------------------
    // C. Insertion sécurisée dans la BDD (Requête préparée)
    // ----------------------------------------------------
    $sql = "INSERT INTO utilisateurs (nom, email, mot_de_passe) VALUES (?, ?, ?)";
    try {
        $stmt = $pdo->prepare($sql);
        // Exécution de la requête en liant les valeurs (prévient les injections SQL)
        $stmt->execute([$nom, $email, $mdp_hache]);
        
        echo "✅ Inscription réussie ! L'utilisateur $nom a été ajouté.";
    } catch (\PDOException $e) {
        if ($e->getCode() == 23000) { // Code d'erreur pour double entrée (ex: email déjà utilisé)
            echo "❌ Erreur : Cet email est déjà utilisé.";
        } else {
            echo "❌ Erreur d'insertion dans la base de données : " . $e->getMessage();
        }
    }
}
?>