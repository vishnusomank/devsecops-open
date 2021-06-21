 

 <div class="thumbnail">
    <!--
        <img class="img-responsive" src="http://placehold.it/800x300" alt="">
    -->
    <div class="caption-full">
        <h4><a href="#">Cross Site Scripting (XSS) – Stored</a></h4>
        
        <p align="justify">
Stored Cross Site Scripting attacks happen when the application doesn’t validate user inputs against malicious scripts, and it occurs when these scripts get stored on the database. Victim gets infected when they visit web page that loads these malicious scripts from database. For instances, message forum, comments page, visitor logs, profile page, etc.         </p>
        <p>Read more about Stored XSS <br>
        <strong><a target="_blank" href="https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)#Stored_XSS_Attacks">https://www.owasp.org/index.php/Cross-site_Scripting_(XSS)#Stored_XSS_Attacks</a></p></strong>

    </div>


</div>

<div class="well">
    <div class="col-lg-6"> 
        <p>  <h4>Post Your Comments </h4>
            <form method='post' action=''>
                <div class="form-group"> 
                    <label></label>
                    <b>Enter Name</b>
                    <input class="form-control" placeholder="Anonymous" name="name"></input> <br>
                    <b>Enter Comment</b>
                    <textarea class="form-control" name="msg"> </textarea> <br>
                    <div align="right"> <button class="btn btn-default" type="submit">Submit Button</button></div>
               </div> 
            </form>
        </p>
    </div>
        <hr>
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
        
        include_once('../../config.php');

        $user = xss_clean(isset($_POST['name']) ? $_POST['name'] : '');
        $comment = xss_clean(isset($_POST['msg']) ? $_POST['msg'] : '');
        if($comment){
            if(!$user){
                $user = "Anonymous";
            }
            $today = date("d M Y");
            $sql="insert into comments (user,comment,date) values(:user,:comment,:date)";
            $stmt = $conn1->prepare($sql);
            $stmt->bindParam(":user",$user);
            $stmt->bindParam(":comment",$comment);
            $stmt->bindParam(":date",$today);
            $stmt->execute();

        }

        $stmt = $conn1->prepare("select user,comment,date from comments"); 
        $stmt->execute();
        while($rows = $stmt->fetch(PDO::FETCH_NUM)){
            echo "<div class=\"row\">";
                echo "<div class=\"col-md-12\">";
                echo "<span class=\"glyphicon glyphicon-star\"></span> &nbsp;";
                    echo ucfirst($rows[0]);
                echo "<span class=\"pull-right\">".$rows[2]."</span>";
                echo "<p>".$rows[1]."</p>";
                echo "</div>";
                echo "</div><hr>";
        } 

        ?>

        <hr>

        

</div>
<?php include_once('../../about.html'); ?>