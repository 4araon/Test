<?php
session_start();

$servername = "localhost";
$username = "root";
$password = "root";
$dbname = "Ayunt";
$port = 8889;

// Crear conexión
$conn = new mysqli($servername, $username, $password, $dbname, $port);

// Verificar conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Mensaje de error
$error = '';

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $usuario = $_POST['usuario'];
    $contraseña = $_POST['contraseña'];

    // Verificar si es el administrador "Franco"
    if ($usuario === 'Franco' && $contraseña === '*MC*2024') {
        $_SESSION['usuario'] = $usuario;
        $_SESSION['tipo_usuario'] = 'Administrador';
        header("Location: dashboard_admin.php");
        exit();
    }
       // Verificar si es el administrador "PRESIDENCIA"
       if ($usuario === 'PRESIDENCIA' && $contraseña === '*MC*PRESIDENCIA') {
        $_SESSION['usuario'] = $usuario;
        $_SESSION['tipo_usuario'] = 'Administrador';
        header("Location: dashboard_P.php");
        exit();
    }
     // Verificar si es el administrador "DIF"
     if ($usuario === 'DIF' && $contraseña === '*DIF*2024') {
        $_SESSION['usuario'] = $usuario;
        $_SESSION['tipo_usuario'] = 'Administrador';
        header("Location: dashboard_D.php");
        exit();
    }
      // Verificar si es el administrador "CONTRALORIA"
      if ($usuario === 'CONTRALORIA' && $contraseña === '2024-2027') {
        $_SESSION['usuario'] = $usuario;
        $_SESSION['tipo_usuario'] = 'Administrador';
        header("Location: dashboard_C.php");
        exit();
    } else {
        // Consultar la base de datos para verificar el usuario y la contraseña
        $sql = "SELECT nombre, pass FROM Autorizadores WHERE nombre = ?";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("s", $usuario);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $stmt->bind_result($nombre, $hashed_password);
            $stmt->fetch();

            // Verificar la contraseña
            if (password_verify($contraseña, $hashed_password)) {
                $_SESSION['usuario'] = $nombre;
                $_SESSION['tipo_usuario'] = 'Usuario';
                header("Location: dashboard.php");
                exit();
            } else {
                $error = "Contraseña incorrecta.";
            }
        } else {
            $error = "Usuario no encontrado.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inicio de Sesión</title>
    <link rel="stylesheet" href="login.css">
</head>
<body>
    <div class="login-container">
        <h1>Inicio de Sesión</h1>
        <form method="post" action="login.php">
            <label for="usuario">Usuario:</label>
            <input type="text" id="usuario" name="usuario" required>

            <label for="contraseña">Contraseña:</label>
            <input type="password" id="contraseña" name="contraseña" required>

            <button type="submit">Iniciar Sesión</button>
        </form>
        <?php if ($error): ?>
            <p class="error"><?php echo htmlspecialchars($error); ?></p>
        <?php endif; ?>
    </div>
</body>
</html>
