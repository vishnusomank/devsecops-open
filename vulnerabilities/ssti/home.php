 

 <div class="thumbnail">
    <!--
        <img class="img-responsive" src="http://placehold.it/800x300" alt="">
    -->
    <div class="caption-full">
        <h4><a href="#">Server Side Template Injection (SSTI)</a></h4>
        
        <p align="justify">
Web application uses templates to make the web pages look more dynamic. Template Injection occurs when user input is embedded in a template in an unsafe manner. However in the initial observation, this vulnerability is easy to mistake for XSS attacks. But SSTI attacks can be used to directly attack web servers’ internals and leverage the attack more complex such as running remote code execution and complete server compromise.          </p>
        <p>Read more about Server Side Template Injection (SSTI)<br>
        <strong><a target="_blank" href="http://blog.portswigger.net/2015/08/server-side-template-injection.html">http://blog.portswigger.net/2015/08/server-side-template-injection.html </a></p></strong>

    </div>

</div>

<div class="well">
    <div class="col-lg-6"> 
        <p>
        Hints: <br>
        <ul>
        <li>Template Engine used is TWIG </li>
        <li>Loader function used = "Twig_Loader_String" </li>
        </ul>
        </p>
        <p>
            <form method='get' action=''>
                <div class="form-group"> 
                    <label></label>
                    <input class="form-control" width="50%" placeholder="Enter Your Name" name="name"></input> <br>
                    <div align="right"> <button class="btn btn-default" type="submit" name='submit'>Submit Button</button></div>
               </div> 
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
                    $name=xss_clean(htmlspecialchars($_GET['name']));
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
                            $result= xss_clean($twig->render($name));
                            echo "Hello $result";
  
                    } catch (Exception $e) {
                          die ('ERROR: ' . $e->getMessage());
                        }
                    }

            ?>
        </p>
    </div>
      
    <hr>

</div>
<?php include_once('../../about.html'); ?>