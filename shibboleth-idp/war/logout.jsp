<%@page import="edu.internet2.middleware.shibboleth.idp.session.Session" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.session.ServiceInformation" %>
<%@page import="edu.internet2.middleware.shibboleth.idp.profile.saml2.SLOProfileHandler" %>
<%@page import="org.owasp.esapi.Encoder" %>
<%@page import="org.owasp.esapi.ESAPI" %>
<html>
  <head>
    <title>Logout Page</title>
    <script language=javascript>
	function redirect(){
  	   window.location = "https://portal.geni.net";
        }
    </script>
  </head>

  <body onload="redirect()">
	
  </body>
</html>
