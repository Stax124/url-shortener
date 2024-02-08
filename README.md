Flask Start OneFile
=========================

[flask]: https://flask.palletsprojects.com

Tento repositář má vám i mě usnadnit založení nového projektu pro framework
[Flask][]. Zde najdete základní adresářovou strukturu pro aplikaci a kostru
aplikace.

Pokud je aplikace složitější a místo jednoho souboru chce balíček, mrkněte se na
[Flask Start](https://github.com/spseol/flask-start)


## ... jak na to?


Dejme tomu že začínám nový projekt. Bude se jmenovat třeba *Foo*. Můžete si
repositář [forknout](htts://help.github.com/articles/fork-a-repo/) nebo
[naklonovat](https://help.github.com/articles/cloning-a-repository/) ale
nejlepší je **[použít
šablonu](https://github.com/spseol/flask-start-onefile/generate)** -- tím se
vytvoří váš vlastní repositář s novou historií a ten si
[naklonujete](https://help.github.com/articles/cloning-a-repository/).


Repositář obsahuje skript **`start.sh`**, který vše další udělá za vás.
  * vytvoří virtuální prostředí
  * nainstaluje potřebné balíčky
  * přestane sledovat .env
  * smaže sám sebe

Pokud chcete mít kontrolu, můžete pokračovat a všechno si pěkně udělat [růčo](#růčo).

VSCode
-----------

V souboru [settings.json](.vscode/settings.json) je nastavení, které vám zajistí
očekávané chování VSCode.

```json
{
  "files.associations": {
    "*.html": "jinja-html"
  },
  "emmet.includeLanguages": {
    "jinja-html": "html",
    "vue-html": "html"
  }
```

Doporučuji ještě doinstalovat si následující rozšíření:
  * aby se vám lépe psalo:
    * [Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python)
    * [Happy Flasker](https://marketplace.visualstudio.com/items?itemName=apedroed.Happy-Flasker)
    * [Better Jinja](https://marketplace.visualstudio.com/items?itemName=samuelcolvin.jinjahtml)
  * aby se vám lépe pracovalo s Gitem
    * [Git Extension Pack](https://marketplace.visualstudio.com/items?itemName=donjayamanne.git-extension-pack)
  * aby se vám automaticky znovu načetla stránka v prohlížeči při změně zdrojového kódu
    * [Live Reload](https://marketplace.visualstudio.com/items?itemName=Phu1237.live-reload)

LiveReload
----------------

LiveReload je udělátko, které slouží k automatickému znovu-načtení webové
stránky při vývoji webových aplikací. 

* Na jedné straně je vždy [rozšíření v prohlížeči](https://chrome.google.com/webstore/detail/livereload/jnihajbhpnppcggbcgedagnkighmdlei)
  nebo [JS knihovna](https://github.com/livereload/livereload-js).
* Na druhé straně je aplikace, která hlídá změny v souborech a pokud se něco
  změní pošle do prohlížeče povel k znovu-načtení stránky. Tato aplikace má více
  různých implementací:

* [VSCode](https://marketplace.visualstudio.com/search?term=livereload&target=VSCode&category=All%20categories&sortBy=Relevance):
  <https://marketplace.visualstudio.com/items?itemName=Phu1237.live-reload> nebo 
  <https://marketplace.visualstudio.com/items?itemName=thebearingedge.livereload-server>
* Python: <https://livereload.readthedocs.io/en/latest/>
* Ruby: <https://github.com/guard/guard-livereload>

### Jak si rozjet Live Reload

1. Nainstalujete si [rozšíření do prohlížeče](https://chrome.google.com/webstore/detail/remotelivereload/jlppknnillhjgiengoigajegdpieppei)
2. Nainstalujete si [rozšíření do VSCode](https://marketplace.visualstudio.com/items?itemName=ziishaned.livereload)
3. Ve VSCode přes Ctrl+Shift+P spustíte Liver Reload nebo si v nastavení zapnete, aby se spuštělo samo při startu VSCode
4. V prohlížeči kliknete na ikonku, aby se provedlo spojení VSCode a prohlížeče.

A je to!

Několik užitečných odkazů pro začátek
------------------------------------------

* [Flask docs][flask]
* [Flask Quick start](https://flask.palletsprojects.com/quickstart/)
* [Template Designer Documentation](https://jinja.palletsprojects.com/templates/)
* [Flask: URLs and paths in request object](https://gist.github.com/MarrekNozka/5f8860465f79b5d39a6aea3b211c4aab#file-urls_and_paths-md)

----------------------------------------------------------------------------

* [Explore Flask](https://exploreflask.com/)
* [The Flask Mega-Tutorial](https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)

---------------------------------------------------------------------------

* <https://github.com/pyvec/elsa>
* <https://github.com/smoqadam/PyFladesk>
* <https://github.com/ClimenteA/flaskwebgui>
* <https://elc.github.io/posts/executable-flask-pyinstaller/>

---------------------------------------------------------------------------

* [Jak psát web](https://www.jakpsatweb.cz/) 
* [w3schools.com](https://www.w3schools.com/) 
* [Blábot](https://www.blabot.cz/)
* [Clker.com](http://www.clker.com/), [Commons](https://commons.wikimedia.org)
* [pixabay](https://pixabay.com/), [Unsplash](https://unsplash.com/)
---------------------------------------------------------------------------

## ...

1. Vytvořím si [virtuální prostředí](https://virtualenv.pypa.io/en/stable/)
   právě pro aplikaci *Foo*.:

```bash
python3 -m venv .venv-foo
```

2. Virtuální prostředí si aktivuji:

```bash
source .venv-foo/bin/activate
```
nebo na Windows:
```
.venv-foo\Scripts\activate

```

3. Do virtuálního prostředí nainstaluji potřebné moduly:

```bash
pip install -r requirements.txt
```
nebo ručně nestručně:

```bash
pip install flask flask-socketio
pip install flask-mail flask-misaka
pip install psycopg2 pony
```


4. A teď stačí spustit vývojový server:

```
flask run
```

