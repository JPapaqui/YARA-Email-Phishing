rule phishing_detection_url
{
    meta:
        description = "Detects phishing URLs"
        author = "Julio Papaqui"
        reference = "Phishing URL"
    strings:
        $url_pattern = "http://{all_ascii}.*?\.[a-z]{2,6}" nocase
        $phishing_keywords = "login|security|verify|account|confirm|bank|paypal|amazon" nocase
    condition:
        $url_pattern and $phishing_keywords
}

//Esta regla busca URL que contengan cualquiera de las palabras clave relacionadas con el phishing especificadas (como "inicio de sesión" o "seguridad"), 
//utilizando una expresión regular que coincida con las URL que comienzan con "http://" y terminan con un dominio de nivel superior. (como ".com" o ".org"). Si
// se encuentra una coincidencia, la regla se activará y alertará al usuario o bloqueará el acceso a la página.
