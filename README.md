# GENI_SAVI
Use the following guide to setup Shibboleth SP, IdP, and OpenLdap:

Use this guide to setup shibboleth: http://www.cybera.ca/news-and-events/tech-radar/getting-started-on-shibboleth/

The shibboleth IdP setup directory is under: https://github.com/rickmcgeer/GENI_SAVI/tree/master/shibboleth-idp. It contains the modified configuration files, and war files for our currently running  Shibboleth setup.

The directory https://github.com/rickmcgeer/GENI_SAVI/tree/master/SAVIFrontEnd contains the service that authenticates GENI users onto SAVI using X509 certificates. It's created in Python Flask.
