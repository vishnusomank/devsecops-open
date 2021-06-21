<html>
<head><title>Server Side Template injection</title></head>
<body><form action="" method="GET">
<label>Enter your Name:</label><br/><input type="text" name="name"><br><br>
<input type="submit" name="submit" value="Enter"><br><br>
</form>
<?php
                //// code snipet to purify url
                function xss_clean($data)
                {
                    // Fix &entity\n;
                    $data = str_replace(array('&amp;','&lt;','&gt;'), array('&amp;amp;','&amp;lt;','&amp;gt;'), $data);
                    $data = preg_replace('/(&#*\w+)[\x00-\x20]+;/u', '$1;', $data);
                    $data = preg_replace('/(&#x*[0-9A-F]+);*/iu', '$1;', $data);
                    $data = html_entity_decode($data, ENT_COMPAT, 'UTF-8');
                    
                    // Remove any attribute starting with "on" or xmlns
                    $data = preg_replace('#(<[^>]+?[\x00-\x20"\'])(?:on|xmlns)[^>]*+>#iu', '$1>', $data);
                    
                    // Remove javascript: and vbscript: protocols
                    $data = preg_replace('#([a-z]*)[\x00-\x20]*=[\x00-\x20]*([`\'"]*)[\x00-\x20]*j[\x00-\x20]*a[\x00-\x20]*v[\x00-\x20]*a[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2nojavascript...', $data);
                    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*v[\x00-\x20]*b[\x00-\x20]*s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:#iu', '$1=$2novbscript...', $data);
                    $data = preg_replace('#([a-z]*)[\x00-\x20]*=([\'"]*)[\x00-\x20]*-moz-binding[\x00-\x20]*:#u', '$1=$2nomozbinding...', $data);
                    
                    // Only works in IE: <span style="width: expression(alert('Ping!'));"></span>
                    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?expression[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
                    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?behaviour[\x00-\x20]*\([^>]*+>#i', '$1>', $data);
                    $data = preg_replace('#(<[^>]+?)style[\x00-\x20]*=[\x00-\x20]*[`\'"]*.*?s[\x00-\x20]*c[\x00-\x20]*r[\x00-\x20]*i[\x00-\x20]*p[\x00-\x20]*t[\x00-\x20]*:*[^>]*+>#iu', '$1>', $data);
                    
                    // Remove namespaced elements (we do not need them)
                    $data = preg_replace('#</*\w+:\w[^>]*+>#i', '', $data);
                    
                    do
                    {
                        // Remove really unwanted tags
                        $old_data = $data;
                        $data = preg_replace('#</*(?:applet|b(?:ase|gsound|link)|embed|frame(?:set)?|i(?:frame|layer)|l(?:ayer|ink)|meta|object|s(?:cript|tyle)|title|xml)[^>]*+>#i', '', $data);
                    }
                    while ($old_data !== $data);
                    
                    // we are done...
                    return $data;
                }
?>
<?php
if (isset($_GET['submit'])) {
$name=xss_clean($_GET['name']);
// include and register Twig auto-loader
include 'vendor/twig/twig/lib/Twig/Autoloader.php';
Twig_Autoloader::register();
try {
  // specify where to look for templates
  $loader = new Twig_Loader_String();
  
  // initialize Twig environment
  $twig = new Twig_Environment($loader);
 // set template variables
 // render template
$result= xss_clear($twig->render($name));
echo "Hello $result";
  
} catch (Exception $e) {
  die ('ERROR: ' . $e->getMessage());
}
}

?>
<p>
  <h3>Hint:</h3>
  <b>1.</b> Template Engine used is TWIG.<br>
  <b>2.</b> Loader function used = "Twig_Loader_String"<br>
</p>

</body>
</html>



