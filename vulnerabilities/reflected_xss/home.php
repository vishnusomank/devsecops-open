 

 <div class="thumbnail">
    <!--
        <img class="img-responsive" src="http://placehold.it/800x300" alt="">
    -->
    <div class="caption-full">
        <h4><a href="#">Cross Site Scripting (XSS) – Reflected</a></h4>
        
        <p align="justify">
        Cross Site Scripting attacks abuse the browser’s functionality to send malicious scripts to the client machine. In other words, this is client side attack. Cross Site Scripting attacks are generally be categorized into two categories: stored and reflected. In reflected attacks, the application reflects the malicious script back on the browser. The server doesn’t store anything, rather just send back whatever user inputs, for instance, error messages, search results etc. Such attacks are campaigning via different routes such as emails, chats, or on third party web sites.  
        </p>
        <p>Read more about Reflected XSS<br>
        <strong><a target="_blank" href="https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Reflected_XSS_.28AKA_Non-Persistent_or_Type_II.29">https://www.owasp.org/index.php/Types_of_Cross-Site_Scripting#Reflected_XSS_.28AKA_Non-Persistent_or_Type_II.29 </a></p></strong>

    </div>

</div>

<div class="well">
    <div class="col-lg-6"> 
        <p>Enter your message here.  
            <form method='get' action=''>
                <div class="form-group"> 
                    <label></label>
                    <input class="form-control" width="50%" placeholder="Enter URL of Image" name="item"></input> <br>
                    <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
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
                if (isset($_GET['item'])) {
                    $val=xss_clean(htmlspecialchars($_GET['item'])); 
                    echo($val);          
                }
                
            ?>
        </p>
    </div>
      
    <hr>
    
</div>
<?php include_once('../../about.html'); ?>
