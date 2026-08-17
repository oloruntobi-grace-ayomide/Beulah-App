from livereload import Server
from starter import app  # reuses your existing app setup — nothing duplicated

server = Server(app)
server.watch('beulah_pkg/templates/')   # any .html change triggers a refresh
server.watch('beulah_pkg/static/')      # any .css/.js change triggers a refresh
server.serve(port=8060, host='127.0.0.1')