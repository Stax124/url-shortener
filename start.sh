#!/bin/sh
# * nainstaluje virtuální prostředí
# * nainstaluje závislosti přes PIP
# * zakáže v Gitu .env
# * smaže se
############################################################

DIRNAME=$(dirname $0)
cd $DIRNAME
BASENAME=$(basename $PWD)

python3 -m venv .venv-${BASENAME}
. .venv-${BASENAME}/bin/activate

pip install -U pip
pip install -r requirements.txt

git rm --cached .env

echo "\nMůžu se smazat? Y/n"
read anone
if [ -z $anone ] || [ $anone != n ]; then
    git rm $(basename $0)
else
    echo "... no dobře, ale být tebou, tak bych mě vymazal!"
fi

#git commit -m 'new Init'

echo "Pro aktivaci virtuálního prostředí použij:

source .venv-${BASENAME}/bin/activate

nebo

. .venv-${BASENAME}/bin/activate

" 
