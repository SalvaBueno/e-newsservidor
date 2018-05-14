#!/bin/bash
NOMBRE_ENTORNO=universitariosApuros
# finalizar con la barra siempre que sea directorios
RUTA_ENTORNO=/home/brian/entornos/
DIRECTORIO_PROYECTO=/home/brian/git/Django/universitariosApuros/
ARCHIVO_WSGI=${DIRECTORIO_PROYECTO}configuracion/apache.wsgi


# creacion del archivo de configuracion de apache
ARCHIVO_CONF_APACHE=/home/brian/pruebas/${NOMBRE_ENTORNO}.conf

SERVER_NAME=universitarios.dreamsappscreative.es
SERVER_ALIAS=universitarios.dreamsappscreative.es
ARCHIVO_LOG=/root/${NOMBRE_ENTORNO}.log



while true
do
    echo "-------------- MENU ----------------"
    echo "1 crear entorno virtual"
    echo "2 arrancar entorno virtual"
    echo "3 instalar paquetes requirements del proyecto"
    echo "4 comprobar paquetes instalados"
    echo "5 crear archivo.conf"
    echo "6 activar archivo.conf"
    echo "7 desactivar archivo.conf"
    echo "8 crear archivo.wsgi"
    echo "9 migracion base datos"
    echo "0 salir"
    echo "-------------- MENU ----------------"

    echo "Elija una opcion del menu:"

    read opcion
    case $opcion in

        0)
        echo "------------------------------------------"
        echo "Saliendo"
        exit 1
        ;;


        1)
        echo "------------------------------------------"
        echo "Ruta entorno:" $rutaEntorno

        # creamos el directorio para los entornos en caso de que no esten
        if [ ! -d $RUTA_ENTORNO ]
        then
            echo "El directorio del entorno no existe, creando directorio"
            mkdir -p "$RUTA_ENTORNO"
        fi

        # creamos el entornovirtual
        echo "Creando entorno virtual"
        virtualenv $RUTA_ENTORNO$NOMBRE_ENTORNO
        echo "------------------------------------------"
        ;;



        2)
        # arrancamos el entornovirtual
        echo "------------------------------------------"
        echo "para dejar iniciado el entorno virtual despues de cerrar, debe iniciar este script con SOURCE delante"
        source ${RUTA_ENTORNO}${NOMBRE_ENTORNO}/bin/activate
        echo "entorno iniciado"
        echo "------------------------------------------"
        ;;


        3)
        echo "------------------------------------------"
        if [ $VIRTUAL_ENV ]
        then
            pip install -r ${DIRECTORIO_PROYECTO}requirements
        else

            echo "Debe iniciar el entorno virtual (opcion 2)"

        fi
        echo "------------------------------------------"
        ;;


        # opcion para ver los paquetes que tiene instalado el virtualenv
        4)
        echo "------------------------------------------"
        if [ $VIRTUAL_ENV ]
        then
            pip freeze
        else
            echo "Debe iniciar el entorno virtual (opcion 2)"

        fi
        echo "------------------------------------------"
        ;;



        # opcion para crear el archivo de apache
        5)
        echo "------------------------------------------"
        . ${DIRECTORIO_PROYECTO}instalacion/archivo_conf
        echo "------------------------------------------"
        ;;


        # opcion para arrancar un archivo conf de apache
        6)
        a2ensite $ARCHIVO_CONF_APACHE
        service apache2 restart
        ;;


        # opcion para desactivar un archivo conf de apache
        7)
        a2dissite $ARCHIVO_CONF_APACHE
        service apache2 restart
        ;;

        # opcio para crear archivo wsgi para apache
        8)
        . ${DIRECTORIO_PROYECTO}instalacion/archivo_wsgi
        ;;

        # opcion para migrar la base de datos
        9)
        echo "------------------------------------------"
        if [ $VIRTUAL_ENV ]
        then
            python ${DIRECTORIO_PROYECTO}manage.py makemigrations
            python ${DIRECTORIO_PROYECTO}manage.py migrate
        else
            echo "Debe iniciar el entorno virtual (opcion 2)"

        fi
        echo "------------------------------------------"
        ;;



    esac
done
