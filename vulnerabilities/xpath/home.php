<?php
$result = '';
if(isset($_POST['submit'])){
$doc = new DOMDocument;
$doc->load('coffee.xml');
$xpath = xss_clean(new DOMXPath($doc));
$input = xss_clean($_POST['search']);
$query = "/Coffees/Coffee[@ID='".$input."']";

#$result = isset($xpath->query($query)) ? $xpath->query($query) : '';
$result = $xpath->query($query);
}
?>
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
<div class="thumbnail">
    <!--
        <img class="img-responsive" src="http://placehold.it/800x300" alt="">
    -->
    <div class="caption-full">
        <h4><a href="#">XPATH Injection </a></h4>
        
        <p align="justify">
XPTH injections are fairly similar to SQL injection with a difference that it uses XML Queries instead of SQL queries. This vulnerability occurs when application does not validate user-supplied information that constructs XML queries. An attacker can send malicious requests to the application to find out how XML data is structured and can leverage the attack to access unauthorized XML data.         </p>
        <p>Read more about XPTH Injection<br>
        <strong><a target="_blank" href="https://www.owasp.org/index.php/XPATH_Injection">https://www.owasp.org/index.php/XPATH_Injection</a></p></strong>

    </div>

</div>

<div class="well">
    <div class="col-lg-6"> 
        <p><b>Search Your Coffee</b>
            <form method='POST' action=''>
                <div class="form-group"> 
                    <label></label> 
                    <input type="text" class="form-control" placeholder="Search by ID" name="search" value="<?php if(isset($input)){echo $input;}?>"> </input> <br>
                    <div align="right"> <button class="btn btn-default" name="submit" type="submit">Search</button></div>
               </div> 
            </form>
        
        </p>

    </div>
      
    <?php
        if (is_array($result) || is_object($result)){
            echo "<table><tr><th>ID</th><th>&nbsp;&nbsp;</th><th>Item & Description</th></tr>";
            foreach($result as $row){
                echo " ";
                echo "<tr><td valign=\"top\">".$row->getElementsByTagName('ID')->item(0)->nodeValue."</td><td>&nbsp;&nbsp;</td>";
                echo "<td valign=\"top\"><b>".$row->getElementsByTagName('Name')->item(0)->nodeValue."</b><br>".$row->getElementsByTagName('Desc')->item(0)->nodeValue."</td></tr>";
                echo "<tr><td colspan=2>&nbsp;</td></tr>";
            }
            echo "</table>";
        }else{
            echo "Item Not Found.";
        }
    ?>

    <hr>
    
</div>
<?php include_once('../../about.html'); ?>
