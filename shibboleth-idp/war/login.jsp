<!DOCTYPE html>

<%@ taglib uri="urn:mace:shibboleth:2.0:idp:ui" prefix="idpui" %>
<html>
  <head>
    <meta charset="utf-8" />
    <title>SAVI Login</title>
    <link rel="stylesheet" type="text/css" href="<%= request.getContextPath()%>/login.css"/>
  </head>

  <body>
    <div class="wrapper">
      <div class="container">
        <header>

	    <div id="header" style="background:url(http://www.savinetwork.ca/wp-content/themes/third-style/images/headers/abstract2.jpg) no-repeat top left;height:150px;width:800px;">
		<div id="site-title">
          	    <span>
            		<a href="http://www.savinetwork.ca/" title="Smart Applications on Virtual Infrastructure" rel="home">Smart Applications on Virtual Infrastructure</a>
             	   </span>
            	</div>
	    </div>
        </header>
    
        <div class="content">
          <div>
            <% if(request.getAttribute("actionUrl") != null){ %>
              <form id="login" action="<%=request.getAttribute("actionUrl")%>" method="post">
            <% }else{ %>
              <form id="login" action="j_security_check" method="post">
            <% } %>

              <% if ("true".equals(request.getAttribute("loginFailed"))) { %>
                <section>
                  <p class="form-element form-error">Login has failed. Double-check your username and password.</p>
                </section>
              <% } %>

<legend>
  Log in using your SAVI credentials
</legend>
              <section>
                <label for="username">Username</label>
                <input class="form-element form-field" name="j_username" type="text" value="">
              </section>

              <section>
                <label for="password">Password</label>
                <input class="form-element form-field" name="j_password" type="password" value="">
              </section>

              <section>
                <button class="form-element form-button" type="submit">Login</button>
              </section>
            </form>
            
            <%
              //
              //    SP Description & Logo (optional)
              //    These idpui lines will display added information (if available
              //    in the metadata) about the Service Provider (SP) that requested
              //    authentication. These idpui lines are "active" in this example
              //    (not commented out) -- this extra SP info will be displayed.
              //    Remove or comment out these lines to stop the display of the
              //    added SP information.
              //
              //    Documentation: 
              //      https://wiki.shibboleth.net/confluence/display/SHIB2/IdPAuthUserPassLoginPage
              //
              //    Example:
            %>

          </div>
          <%--<div class="column two">
            <ul class="list list-help">
              <li class="list-help-item"><a href="#"><span class="item-marker">&rsaquo;</span> Forgot your password?</a></li>
              <li class="list-help-item"><a href="#"><span class="item-marker">&rsaquo;</span> Need Help?</a></li>
              <li class="list-help-item"><a href="https://wiki.shibboleth.net/confluence/display/SHIB2/IdPAuthUserPassLoginPage"><span class="item-marker">&rsaquo;</span> How to Customize this Skin</a></li>
            </ul>
          </div> --%>
        </div>
      </div>

      <footer>
        <div class="container container-footer">
<div id="footer" role="contentinfo">
    <div id="colophon">

      <div id="site-info">
        <a href="http://www.savinetwork.ca/" title="Smart Applications on Virtual Infrastructure" rel="home">
          Smart Applications on Virtual Infrastructure        </a>
      </div><!-- #site-info -->


      <div id="copyright">
        Copyright @ 2011-2015, <a href="http://www.savinetwork.ca">SAVI</a>
      </div>

    </div><!-- #colophon -->
</div>	
        </div>
      </footer>
    </div>
    
  </body>
</html>
