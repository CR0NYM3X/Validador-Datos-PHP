<?php

// https://www.uno-de-piera.com/validar-con-expresiones-regulares-en-php/s
class tool
{
#validaciones: https://informaticapc.com/tutorial-php/validar-formulario.php
/*
//htmlspecialchars();
//htmlentities()
#htmlspecialchars(utf8_decode
#mysqli_real_escape_string
addslashes


ACTUALIZAR HERRAMIENTA PARA CUANDO SE AGA UNA SOLICITUD A UNA FUNCION Y SE RETORNE UN FALSE QUE TAMBIEN RETORNE EL PORQUE DEL FALSE 
UTILIZANDO &$errror
*/

    private  $METHOD="AES-256-CFB";  //metodos de cifrado http://php.net/manual/es/public function.openssl-get-cipher-methods.php
    private  $SECRET_KEY="?.?:[)()]Hola";
    private  $SECRET_IV="0987654321234567";
    public  $conexiondb=false;
    private $token;
    private $VarResultMysql=null;
	//http://www.anieto2k.com/2009/03/18/20-librerias-php-para-usar-cada-dia/


    public function LimiteCaracter($string,$limit,&$error=null)
    {
        if(strlen($string)<=$limit)
        {
            return true;
        }
        else
        {
            return false;
        }

    }

    public function TieneEspacio()
    {

    }
  
    /*Valida si Son solo numeros lo que se ingresaron*/
	public function EsNumero($var,&$error=null,$limit=null)
	{
        if(trim($var))
        {
    		//return is_numeric($var);
            if(preg_match("/^[0-9\s]+$/", $var))
            {
                if(isset($limit))
                {      
                    if (strlen($var)<=$limit)
                    {
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }
                return true;
            }
            else
            {
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }
	}

    /* Quita los espacios de un string*/
    public function QuitarEspacio($var)
    {
        $text = preg_replace("[\s+]","", $var);
        return $text;

    }

    /* Valida si el string esta en fomato de telefono*/
    public function EsTelefono($var,&$error=null,$limit=null)
    {
         if(trim($var))
        {
            if(preg_match("/^[0-9-+()\s]+$/", $var))
            {
                if(isset($limit))
                {      
                    if (strlen($var)<=$limit)
                    {
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }
                return true;
            }
            else
            {                
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }
        
    }


    /*Valida si es puro string*/
	public function EsTexto($var,&$error=null,$limit=null)
	{

        if(trim($var))
        {
            if(preg_match("/^[a-zA-ZáéíóúäëïöüñÄËÏÖÜÁÉÍÓÚÑ\s]+$/", $var))
            {
                if(isset($limit))
                {      
                    if (strlen($var)<=$limit)
                    {
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }
                return true;
            }
            else
            {
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }

		
	}

    /*Valida si es puro string o numero*/
    public function EsNumeroyTexto($var,&$error=null,$limit=null)
    {

        if(trim($var))
        {
            if(preg_match_all("/^[a-zA-Z0-9áéíóúäëïöüñÄËÏÖÜÁÉÍÓÚÑ\s]+$/", $var))
            {
                if(isset($limit))
                {      
                    if (strlen($var)<=$limit)
                    {
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }
                return true;
            }
            else
            {
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }
    }


   /*Valida si es puro string o numero*/
    public function Caracteres($var,&$error=null,$limit=null)
    {

        if(trim($var))
        {
            if(preg_match_all("/^[a-zA-Z0-9áéíóúäëïöüñÄËÏÖÜÁÉÍÓÚÑ\-\.\_\#\s]+$/", $var))
            {
                if(isset($limit))
                {      
                    if (strlen($var)<=$limit)
                    {
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }
                return true;
            }
            else
            {
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }
    }



    /*Valida si esta en formato de  correo */
    public function EsCorreo($correo,&$error=null,$limit=null)
    {

        if(trim($correo))
        {
            if (preg_match_all("/^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.([a-zA-Z]{2,6})$/", $correo)) 
            {
                if(isset($limit))
                {      
                    if (strlen($correo)<=$limit)
                    {
                        #MODIFICARLE PARA QUE RETORNE EL CORREO EN MINUSCIULA
                        return true;
                    }
                    else
                    {
                        $error="Se exedieron los caracteres permitidos que son: ".$limit;
                        return false;
                    }
                }

                #MODIFICARLE PARA QUE RETORNE EL CORREO EN MINUSCIULA
                return true;

            }
            else
            {
                $error="Se ingresaron caracteres no validos";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }

    }

    public function EncodearImg64($rutaimg,$tipoImagen=null,&$error=null)
    {

        if(!($archivo=fopen($rutaimg, "r")))
        {
            $error="No se pudo leer el archivo Porfavor de volver a intentar";
            fclose($archivo);
            return false;
        }
        if(!($contenidobyte=fread($archivo, filesize($rutaimg))))
        {
            $error="No se pudo leer el archivo Porfavor de volver a intentar";
            fclose($archivo);
            return false;
        }
        fclose($archivo);

        if(isset($tipoImagen))
        {
            return "data:$tipoImagen; base64,".base64_encode($contenidobyte);
        }
        else
        {

               // Tipos de imagen.
            $tiposimg = array(
                1 => "gif",
                2 => "jpeg",
                3 => "png",
                4 => "swf",
                5 => "psd",
                6 => "bmp",
                7 => "tiff",
                8 => "tiff"
            );

            #verifica el tipo de imagen
            if(!($idTipo= exif_imagetype($rutaimg)))
            {
                $idTipo=2;
            }

            return "data:image/".$tiposimg[$idTipo]."; base64,".base64_encode($contenidobyte);
        }
    }

    #ESTA FUNCION NOS AYUDA A VALIDAR UNA IMAGEN EN CASO DE UTILIZAR UN UPLOAD PARA VER SI ES VIABLE PODERLA SUBIRLA AL SERVIDOR, SI SE ENCONTRO ALGUNA ANOMALIA EN LA IMAGEN RETORNANDO FALSE Y SU PORQUE DIO RETORNO FALSE.
    public function ValidarImagen($rutaimg,&$error,&$ImgEncoding,$limitkb,$formato,$ValidarNombre)
    {

        if($rutaimg=="")
        {
            $error="No se encontro ninguna imagen";
            return false;
        }

        ###aplicar filto :   áéíóúÄËÏÖÜÁÉÍÓÚÑñ
        if(!preg_match("/^[a-zA-Z0-9+-áéíóúÄËÏÖÜÁÉÍÓÚÑñ\.\_\s]+$/", $ValidarNombre))
        {
            $error="El nombre de la imagen contiene caracteres no permitidos";
            return false;
        }
        
        if(!preg_match_all("#(image/jpeg|image/jpg|image/gif|image/png)#", $formato))
        {
            $error="El formato de imagen no es permitido los formatos permitidos son : .jpg .jpeg .png .gif";
            return false;
        }

        if(filesize($rutaimg)==0)
        {
            $error="Error la imagen pesa 0";
            return false;
        }

        if(filesize($rutaimg)>$limitkb)
        {
            $error="La imagen pesa mas de lo permitido que es: ".$limitkb." KB";
            return false;
        }

        if(!($archivo=fopen($rutaimg, "r")))
        {
            $error="No se pudo leer el archivo Porfavor de volver a intentar";
            fclose($archivo);
            return false;
        }
        if(!($contenidobyte=fread($archivo, filesize($rutaimg))))
        {
            $error="No se pudo leer el archivo Porfavor de volver a intentar";
            fclose($archivo);
            return false;
        }
        fclose($archivo);
        if (preg_match_all("#(\<\?php|eval\(|phpinfo\(|preg_match|str_replace|base64|crypt|encode|decode|preg_replace)#i", $contenidobyte))
        {
            $error="La imagen Contiene Codigo Malicioso.";
            return false;
        }

        return true;
         

    }


    #Funcion que no sirve para guardar una imagen en el servidor cambiando su nombre y desencondeandolo de base64.
    function GuardarArchivo64($ruta,$ImgEncod,$tipo=null,&$error=null)
    {

        #Esto sirve para verificar si se puso la extencion que se quiere para la imagen si no se pone por defaul sera .jpg
        if(!isset($tipo))
        {
            $tipo=".jpg";
        }
        else
        {
            if(preg_match("#/#", $tipo))
            {
                $tipo=".".explode("/", $tipo)[1];
            }
            elseif(preg_match("#\.#", $tipo))
            {
                $tipo=".".explode(".", $tipo)[1];
            }
            else
            {
                $tipo=".$tipo";
            }
        }

        #Creara un nombre aleatorio para la imagen por seguridad se cambia
        $nameImg=md5(rand().date("F j, Y, g:i a").rand().time());

        #Aqui lo que hace es crear la imagen en la retua espesificada y desencodear el base64 de la imagen y el resultado ingresarlo en el archivo creado, esta funcion retorna el nombre de la imagen para saber como  se llama por si se guardara en una base de datos...
        if(($file=fopen($ruta.$nameImg.$tipo, "w+")))
        {
            $ImgEncod=explode(",", $ImgEncod)[1];
            if(fwrite($file, base64_decode($ImgEncod)))
            {
                fclose($file);
                return $nameImg.$tipo;
            }
            else
            {   
                fclose($file);
                $error="No se pudo escribir en el archivo";
                return false;
            }
        }
        else
        {
            fclose($file);
            $error="No se pudo guardar el archivo";
            return false;
        }
    }

    #funcion que nos permite extraer todos los metadatos que se encuentren en una imagen
    public function ExtraerMetadatosImg($ruta,&$error=null)
    {
          // Tipos de imagen.
            $tiposimg = array(
                1 => "gif",
                2 => "jpeg",
                3 => "png",
                4 => "swf",
                5 => "psd",
                6 => "bmp",
                7 => "tiff",
                8 => "tiff"
            );

            #verifica el tipo de imagen
            if(!($idTipo= exif_imagetype($ruta)))
            {
                $idTipo=2;
            }

            $arrrayExif=array();
            if(@exif_thumbnail($ruta))
            {
                $arrrayExif["img64"]="data:image/".$tiposimg[$idTipo]."; base64,".base64_encode(exif_thumbnail($ruta));
            }

            if(($exif=@exif_read_data($ruta,0,true)))
            {

                foreach ($exif as $clave => $sección) 
                {
                    #$arrrayExif[$clave];

                    #echo "<h4>".$clave."</h4>";
                    foreach ($sección as $nombre => $valor) 
                    {
                        
                        if(gettype($valor)=="array")
                        {
                            foreach ($valor as $key => $value) 
                            {
                                $arrrayExif["exif"][$clave][]=$nombre.":  ".$value;
                     #          echo "<br>$nombre: ".$value;
                            }
                        }
                        else
                        {
                            $arrrayExif["exif"][$clave][]=$nombre.":  ".utf8_encode($valor);
                    #       echo "$nombre: ".utf8_encode($valor)."<br />\n";
                        }
                    }
                    #echo "<br><br>";
                }


                return $arrrayExif;
            }
            elseif(isset($arrrayExif["img64"]))
            {
                return $arrrayExif;
            }
            else
            {
                $error="No se Econtraron Metadatos o la imagen no es soportada";
                return false;
            }
    }



    #Valida si una targeta de Credito Es valido por el el algoritmo.
    public function EsCC($cc,&$error=null)
    {
        if(preg_match_all('/^([(4?|5?|6?)][\d]{15}|[3][\d]{14})$/',$cc))
        {
            $odd = true;
            $sum = 0;
            foreach ( array_reverse(str_split($cc)) as $num) {
            $sum += array_sum( str_split(($odd = !$odd) ? $num*2 : $num) );
            }

            if(($sum % 10 == 0) && ($sum != 0))            
            {
                return true;
            }
            else
            {
               $error="Targeta no Valida";
               return false;                
            }
        }
        else
        {
            $error="Targeta no Valida";
            return false;
        }
    }


    public function validarRFC($valor,&$error=null)
    {
        if(trim($valor))
        {
           $valor = str_replace("-", "", $valor);
            $cuartoValor = substr($valor, 3, 1);
            //RFC Persona Moral.
            if (ctype_digit($cuartoValor) && strlen($valor) == 12) {
                $letras = substr($valor, 0, 3);
                $numeros = substr($valor, 3, 6);
                $homoclave = substr($valor, 9, 3);
                if (ctype_alpha($letras) && ctype_digit($numeros) && ctype_alnum($homoclave)) {
                    $error= "RFC Invalido";
                    return true;
                }
            //RFC Persona Física.
            } else if (ctype_alpha($cuartoValor) && strlen($valor) == 13) {
                $letras = substr($valor, 0, 4);
                $numeros = substr($valor, 4, 6);
                $homoclave = substr($valor, 10, 3);
                if (ctype_alpha($letras) && ctype_digit($numeros) && ctype_alnum($homoclave)) {
                    return true;
                }
            }else {
                $error= "RFC Invalido";
                return false;
            }
        }
        else
        {
            $error= "El campo esta vacio";
            return false;
        }
    }

    /*Sirve para enviar correos*/
    public function EnviarCorreo($destino,$asunto,$mensaje)
    {

        $headers="MIME-Version: 1.0\r\n";
        $headers.="Content-type: text/html; charset=iso-8859-1\r\n";  // es para poder mandar mensajes html
        $headers.="From: www.nana.mx < Administrador@nan.mx >\r\n"; //quien lo manda
        $exito=mail($destino, $asunto, $mensaje,$headers);
        if ($exito) 
        {

            return true;
        }
        else
        {
            return false;
        }

    }



    public function ConectarMysql($server,$user,$password,$db,&$error=null)
    {
        $conexion= mysqli_connect($server,$user,$password);
        if ($conexion) 
        {
            if(mysqli_select_db($conexion,$db))
           {
                $this->conexiondb= $conexion;
                mysqli_set_charset($conexion,"utf8");
                return $conexion;    
            }
            else
            {
                $error="No se pudo conectar a la Base de Datos";
                return false;
            }
        }
        else
        {
            $error= "No se pudo conectar al Servidor";
            return false;
        }

    }


    public function ConsultarMysql($consulta,$ExtInArray=null,&$error=null)
    {
            if($resultado= mysqli_query($this->conexiondb,$consulta))
            {


                if (mysqli_num_rows($resultado)!=0) 
                {
                    if(is_null($ExtInArray))
                    {   
                        return $this->VarResultMysql=$resultado;                     
                    }
                    else
                    {
                        return mysqli_fetch_array($resultado, MYSQLI_ASSOC);
                    }
                }
                else
                {
                    $error="No se relizo la opracion con exito favor de volver a intentar";
                    return false;
                }
            }
            else
            {
                $error="No se relizo la opracion con exito favor de volver a intentar";
                return false;
            }
    }

    public function FetchMysql($consulta=null,&$error=null)
    {
         if(is_null($consulta))
        {
            if(!is_null($this->VarResultMysql))
            {
                #SE RECOMIENDA mysqli_fetch_assoc PARA QUE EL ARRAY NO TENGA DE MAS ELEMENTOS YA QUE TIENE ARRAY ASSOC Y NUMERICO
                return mysqli_fetch_array($this->VarResultMysql);

            }
            else
            {
                $error="No se a Consultado nada";
                return false;
            }
        }
        else
        {
             return mysqli_fetch_assoc($consulta);
        }
    }

    public function InsertarMysql($insertar,&$error=null)  #hacer un DELETE  UPDATE INSERT, DuiMysql o RudiMysql ->R=remplace
    {

        if($resultado= mysqli_query($this->conexiondb,$insertar))
        {
            if (mysqli_affected_rows($this->conexiondb)) 
            {
                return true;
            }
            else
            {
                $error="No se relizo la opracion con exito favor de volver a intentar";
                return false;
            }
        }
        else
        {
            $error="No se relizo la opracion con exito favor de volver a intentar";
            return false;
        }
    }

    /*Sirve para generar un token*/
    public function GetToken($var=null)
    {

        return $_SESSION[$_SERVER['REMOTE_ADDR']]["token"]=hash("sha512",base64_encode($var.md5(crypt(base64_encode(time().rand().strlen(rand())),rand()))));
        # Opcional
        /*if (isset($_SESSION["token"])) 
        {
            echo "Ya existe la sesion";
            return $_SESSION["token"];   
        }
        else
        {
         
            return $_SESSION[$_SERVER['REMOTE_ADDR']]["token"]=hash("sha512",base64_encode($var.md5(crypt(base64_encode(time().rand().strlen(rand())),rand()))));
        }*/
    }

    public function GetUsuario(&$error=null)
    {
        if (isset($_SESSION[$_SERVER['REMOTE_ADDR']]))
        {
            return $_SESSION[$_SERVER['REMOTE_ADDR']];
        }
        else
        {
            $error="No se encontro el usuario";
            return false;
        }
    }

    /*Sirve para ver si el token esta correcto*/
    public function CheckToken($tk,&$error=null)
    {
        if($tk==$_SESSION[$_SERVER['REMOTE_ADDR']]["token"])
        {
            return true;
        }
        else
        {   
            $error="Token no Valido";
            return false;
        }

       /*Este metodo es para cuando queremos verificar el toquen por un metodo.
        if (isset($_POST["token"]) && $_POST["token"] == $_SESSION["token"]) 
        {
            return true;
        }
        else
        {
            return false;
        }*/
    }


    /* 
    Esta - Opcion Encriptan lo que quieras y la desencriptas utilizando el metodo decrypt garantizada para las comunicaciones con socket y no se recomienda que lo que se encripte sea menor a de 16 caracteres esta opcion de caracteres es opcional;
    */
    public function Encrypt($ssl){

    $output=openssl_encrypt($ssl, $this->METHOD, $this->SECRET_KEY, 0, $this->SECRET_IV);   
    $output=base64_encode($output);  
    return $output;

    }


    /* Metodo que funcina del resultado que retorna el valor encrypt*/
    public function Decrypt($ssl){

    $output=openssl_decrypt(base64_decode($ssl), $this->METHOD, $this->SECRET_KEY, 0,  $this->SECRET_IV);
    return $output;

    }





    /*Esta opcion es valida para encriptar contraseñas para login o otras cosas que requieran de encriptamiento de contraseñas*/
    public function EncriptarPass($contraseña){
    $hash=password_hash($contraseña, PASSWORD_DEFAULT);
    return $hash;
    }

    /* Metodo que funcina del resultado que retorna el valor EncriptarPass y la contraseña que se escogio uno pero desencriptada*/
    public function DesencriptarPass($contraseña,$hash,&$error=null)
    {

        if(password_verify($contraseña,$hash))
        {
             return true;
        }
        else
        {
              return false;
        }

    }

    public function ValidarPass($clave,&$error=null)
    {
            if(!trim($clave))
            {
                $error= "El campo esta vacio";
                return false;
            }
           if(strlen($clave) < 6){
              $error = "La clave debe tener al menos 6 caracteres";
              return false;
           }
           if(strlen($clave) > 30){
              $error = "La clave no puede tener más de 30 caracteres";
              return false;
           }
           if (!preg_match('/[a-záéíóúäëïöü]/',$clave)){
              $error = "La clave debe tener al menos una letra minúscula";
              return false;
           }        #áéíóúäëïöüñÄËÏÖÜÁÉÍÓÚÑ
           if (!preg_match('/[A-ZÄËÏÖÜÁÉÍÓÚÑ]/',$clave)){
              $error = "La clave debe tener al menos una letra mayúscula";
              return false;
           }
           if (!preg_match('/[0-9]/',$clave)){
              $error = "La clave debe tener al menos un caracter numérico";
              return false;
           }
            if (preg_match('/[\s+]/',$clave)){
              $error = "La clave No debe de tener Espacios";
              return false;
           }
            if (preg_match('/[\.\-\_]/',$clave)){
              $error = "La clave Almenos debe de contener un de estos signos: \. \- \_ ";
              return false;
           }
           return true;
    } 



    #ESTA FUNCION SIRBE PARA FACILITAR LA CREACION DE PAGINACION
    public function Paginacion($NombrePag,$Tabladb,$NumColumTabla,$ClickPage2,$PagMax=20,&$error=null)
    {

        #$NumColumTabla=; #Aqui se pueden poner los numeros de columnas de la tabla que se consultara
       

        #PARTE EN DONDE CONSULTA LA CANTIDAD DE FILAS QUE TIENE LA TABLA
        if(!($TotalPaginas = $this->ConsultarMysql("select count(*) from $Tabladb",1)["count(*)"]))
        {
            $error="No se pudo saber la cantidad de filas.";
            return false;
        }

        #AQUI HACE EL CALCULO PARA SABER CUANTAS PAGINACIONES TENDRA LA TABLA
        $Paginacion=ceil($TotalPaginas/$PagMax);


        #AQUI SE COMPRUEBA QUE EN LA URL EXISTA EN METODO GET LA VARIABLE Y QUE EL VALOR NO SEA 0 SI ES CERO O NO EXISTE LA VARIABLE O NO EL VALOR INGRESADO NO ES UN NUMERO SE RETORNARA A LA URL CON EL GET ?page=1
        if(isset($ClickPage2) and $this->EsNumero($ClickPage2) and $ClickPage2!=0)
        {
            $clickPage=($ClickPage2-1)*$PagMax;
        }
        else
        {
            header("location: $NombrePag?page=1");
        }

        #ESTO SIRVE POR SI SE MANIPULA EL NUMERO DE PAGINA Y SE QUIERE PONER UN NUMERO MAS GRANDE O MENOR QUE LA CANTIDAD DE PAGINAS EXISTENTES
        if($ClickPage2>$Paginacion or $ClickPage2<0)
        {
            
            header("Location: $NombrePag?page=1");   

        }
        

        #AQUI SE HACE LA CONSULTA A LA BASE DE DATOS CON EL LIMITE DE DATOS QUE SE MOSTRARAN EN LA PAGINA.
        if(!($result=$this->ConsultarMysql("select * from $Tabladb limit $clickPage,$PagMax")))
        {
            $error= "No se pudo consultar esta pagina, volver a consultar.";
            return false;
        }

        #Esta parte se puede poner el encabezado de la tabla.
        /*echo "<table id='PaginacionDB' border='1'>
        <tr><th>Id: </th><th>Bin: </th><th>Ciudad: </th><th>Marca: </th><th>Tipo: </th><th>Nivel: </th><th>Banco: </th></tr>
        ";*/


        #WHILE ENCARGADO DE IMPRIMIR LOS DATOS EXTRAIDOS DE LA BASE DE DATOS
        while ($res=$this->FetchMysql(null)) 
        {
            /*print_r(
                # AQUI ES DONDE TIENES QUE PONER LOS NOMBRES DE TUS CAMPOS aqui es mejor recomendado para la velocidad
            '<tr>
        <td align="center">'.$res[0].'</td>
        <td align="center">'.$res[1].'</td>
        <td align="center">'.$res[2].'</td>
        <td align="center">'.$res[3].'</td>
        <td align="center">'.$res[4].'</td>
        <td align="center">'.$res[5].'</td>  
        <td align="center">'.$res[6].'</td>
            </tr>');*/

            if($res["mail"]==($this->GetUsuario()["correo"]))
            {
                echo '<tr><td><a href="editarproducto.php?id='.$res["id"].'" style="text-decoration:none;color:black;"><img src="'.$res["imgpro"].'"  width="100" height="100"></a></td>';
            }
            else
            {
            echo " <tr><td><a href='solprod.php?id=".$res["id"]."'><img src='".$res["imgpro"]."'  width='100' height='100'></a></td>";
            }

                echo "
                            
                            <td>".$res["nombre"]."</td>
                            <td>".$res["contenido"]."</td>
                            <td>".$res["capacidad"]."</td>
                            <td>".$res["lugar"]."</td>
                            <td>".$res["descripcion"]."</td>
                            <td>".$res["f_pago"]."</td>
                            <td>".$res["certificaciones"]."</td>
                            <td>".$res["medida"]."</td>
                            <td>".$res["mail"]."</td>
                        </tr>
                    ";      

/*
            #Esta opcion no es recomendable porque utiliza el for y eso solo retraza la execucion
            echo "<tr>";
            for ($i=0; $i < $NumColumTabla ; $i++) 
            { 
                echo '<td align="center">'.$res[$i].'</td>';
            }

            echo "</tr>";
            #echo "<td><a id='Cssiditar' href='$NombrePag?editar=".$res[0]."'>Editar </a>  <a id='Csseliminar' href='$NombrePag?eliminar=".$res[0]."'> Eliminar</a></td></tr>";*/


        }



        #ESTO SIRVE PARA CUANDO LOS DATOS QUE SE MOSTRARAN SON MAS DE 10 PAGINAS ENTONCES CUANDO SE SELECCIONE UN NUMERO DE PAGINA MENOR QUE 7 Y MAYOR QUE 1 ENTRARA AQUI.
        if($ClickPage2<7 and $ClickPage2>=1 and $Paginacion!=1 and $Paginacion>10)
        {
                echo "<tr><td colspan='$NumColumTabla' height='35'></td></tr>";
                echo "<tr><td  id='CssPaginacion' colspan='$NumColumTabla' align='center'>";
            
                for ($i=1; $i <= 10 ; $i++) 
                { 
                    echo "<a href='$NombrePag?page=$i'>$i</a>  "; 
                }
            
                
                echo "<a href='$NombrePag?page=".($ClickPage2+1)."'>  Siguiente</a>";

                echo "</td></tr>
                <tr><td colspan='$NumColumTabla' height='10'></td></tr>
                <tr><td colspan='$NumColumTabla' align='right'>Pagina: $ClickPage2 de alrededor de $TotalPaginas resultados</td></tr>                
                </table>";
            
        }

        #ESTO SIRVE PARA CUANDO YA ESTA APUNDO DE ACABARSE LAS PAGINAS, ENTONSES NO MOSTRAR MAS PAGINAS DE LAS QUE NO HAY
        elseif($ClickPage2>($Paginacion-9) and $ClickPage2<=$Paginacion and $Paginacion!=1 and $Paginacion>10)
        {
                echo "<tr><td colspan='$NumColumTabla' height='35'></td></tr>";
                echo "<tr><td  id='CssPaginacion' colspan='$NumColumTabla' align='center'>";
                echo "<a href='$NombrePag?page=".($ClickPage2-1)."'>Anterior   </a>";
            
                for ($i=($Paginacion-9); $i <= $Paginacion ; $i++) 
                { 
                    echo "<a href='$NombrePag?page=$i'>$i </a>"; 
                }
            
                echo "</td></tr>
                <tr><td colspan='$NumColumTabla' height='10'></td></tr>
                <tr><td colspan='$NumColumTabla' align='right'>Pagina: $ClickPage2 de alrededor de $TotalPaginas resultados</td></tr>
                </table>";

        }  

        #ESTO SIRVE PARA CUANDO HAY MAS DE 10 PAGINAS ENTRA AQUI.
        elseif($Paginacion!=1 and $Paginacion>10)
        {
                echo "<tr><td colspan='$NumColumTabla' height='35'></td></tr>";
                echo "<tr><td  id='CssPaginacion' colspan='$NumColumTabla' align='center'>";
                echo "<a href='$NombrePag?page=".($ClickPage2-1)."'>Anterior  </a>  ";
            

                for ($i=($ClickPage2-5); $i < (($ClickPage2-5)+10) ; $i++) 
                { 
                    echo "<a href='$NombrePag?page=$i'>$i</a>  "; 
                }
            
            
                echo "<a href='$NombrePag?page=".($ClickPage2+1)."'>  Siguiente</a>";
                
                echo "</td></tr>
                <tr><td colspan='$NumColumTabla' height='10'></td></tr>
                <tr><td colspan='$NumColumTabla' align='right'>Pagina: $ClickPage2 de alrededor de $TotalPaginas resultados</td></tr>
                </table>";

        }

        #ESTO SIRVE PARA CUANDO HAY POCOS DATOS POR MOSTRAR Y HAY MENOS DE 10 PAGINAS ENTRARA AQUI.
        elseif($Paginacion!=1 and $Paginacion<=10)
        {       
                echo "<tr><td colspan='$NumColumTabla' height='35'></td></tr>";
                echo "<tr><td id='CssPaginacion' colspan='$NumColumTabla' align='center'>";
            
                for ($i=1; $i <= $Paginacion ; $i++) 
                { 
                    echo "<a href='$NombrePag?page=$i'>$i</a>  "; 
                }

                echo "</td></tr>
                <tr><td colspan='$NumColumTabla' height='10'></td></tr>
                <tr><td colspan='$NumColumTabla' align='right'>Pagina: $ClickPage2 de alrededor de $TotalPaginas resultados</td></tr>
                </table>";
        }

        return true;
    }


    function __construct()
    {

    $this->SECRET_KEY=hash('sha256', $this->SECRET_KEY);   //se encriptan por precausion
    $this->SECRET_IV=substr(hash('sha256', $this->SECRET_IV),0,16);   //se encriptan por precausion
    
    }

    /*Para ahorar espacio en memoria*/
    function __destruct()
    {
        /*
        if($this->conexiondb!=false)
        {
            mysqli_close($this->conexiondb);
        }*/

        unset($this->METHOD);  //metodos de cifrado http://php.net/manual/es/public function.openssl-get-cipher-methods.php
        unset($this->SECRET_KEY);
        unset($this->SECRET_IV);
        unset($this->conexiondb);
        unset($this->VarResultMysql);

    }

}




?>