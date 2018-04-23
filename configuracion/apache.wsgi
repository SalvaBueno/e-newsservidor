import os, sys, site
 
# Add the site-packages of the chosen virtualenv to work with 
site.addsitedir('/home/brian/pruebas/entornos/lib/python2.7/site-packages')


sys.path.append('/home/brian/git/Django/bosrha/')
sys.path.insert(0,os.sep.join(os.path.abspath(__file__).split(os.sep)[:-2]))

os.environ['DJANGO_SETTINGS_MODULE']='configuracion.settings'

# Activate your virtual env
activate_env=os.path.expanduser('/home/brian/pruebas/entornos/bin/activate_this.py')
execfile(activate_env, dict(__file__=activate_env))

from django.core.wsgi import get_wsgi_application
application = get_wsgi_application()
