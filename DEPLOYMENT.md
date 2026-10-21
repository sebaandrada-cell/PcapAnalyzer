# Publicar una beta gratuita

Esta guía publica el frontend en Vercel (`*.vercel.app`), usa Supabase para
cuentas/datos/almacenamiento y Render para la API. El backend incluye el worker
de análisis en el mismo servicio de Render para evitar un segundo servicio de
pago durante la beta.

**Es una beta, no un despliegue comercial fiable.** El servicio gratuito de
Render puede suspenderse cuando queda inactivo y tardar en volver a responder.
Los límites de recursos y de almacenamiento de los planes gratuitos también
pueden cambiar. Antes de cobrar a clientes, usa servicios de producción,
configura límites de uso y facturación, y prueba recuperación, privacidad y
copias de seguridad. Este repositorio no integra pagos ni planes comerciales.

## 1. Preparar el código en GitHub

Sube el proyecto a un repositorio privado de GitHub. No incluyas archivos `.env`,
claves, contraseñas ni tokens. Render y Vercel leerán el repositorio para
desplegar cada parte.

## 2. Crear un proyecto Supabase independiente

Aunque ya uses Supabase para otros proyectos, crea un proyecto separado para
PcapAnalyzer. No reutilices sus datos ni pegues claves de otros proyectos.

1. En el proyecto nuevo, abre **SQL Editor** y ejecuta el contenido de
   `supabase/migrations/20261021000000_shared_saas_infrastructure.sql`.
2. En **Project Settings → API**, guarda la Project URL, la clave `anon`/
   publishable y la clave `service_role`/secret.
3. En **Project Settings → Database**, copia la URI de conexión PostgreSQL y
   añade `?sslmode=require` (o `&sslmode=require` si la URI ya incluye
   parámetros).
4. En **Authentication → Providers**, habilita Email. Para pruebas cerradas
   puedes deshabilitar temporalmente la confirmación de email; antes de abrir
   el registro, configura SMTP propio y vuelve a exigir confirmación.

La clave `service_role` y la URI de base de datos son secretos del servidor:
guárdalas solo en Render. La clave `anon` se usa en el frontend y no sustituye
la autenticación de cada usuario.

## 3. Desplegar API y worker en Render

1. En Render, elige crear un **Blueprint** desde el repositorio.
2. Render detectará `render.yaml` y pedirá los valores marcados como
   `sync: false`. Rellénalos desde el proyecto Supabase:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - `SUPABASE_DB_URL`
   - `CORS_ORIGINS`: por ahora se puede poner `http://localhost:5173`; más
     adelante añade aquí el dominio `https://<tu-app>.vercel.app`.
3. Despliega el servicio. La URL será similar a
   `https://pcapanalyzer-api.onrender.com`. Comprueba que
   `https://<url-api>/health` devuelve `"status": "ok"` y que `"auth"` informa
   `"mode": "supabase"`.

La configuración conjunta inicia FastAPI y el worker de la cola en el mismo
contenedor. Si uno de los dos procesos falla, el servicio se reinicia y Render
lo vuelve a desplegar.

## 4. Publicar el frontend en Vercel

1. En Vercel, importa el mismo repositorio.
2. En la configuración del proyecto, establece **Root Directory** en `frontend`.
   Usa el comando de build `npm run build` y la carpeta de salida `dist`.
3. Añade estas variables de entorno para **Production** (y Preview si quieres):
   - `VITE_SUPABASE_URL`: la Project URL de Supabase.
   - `VITE_SUPABASE_ANON_KEY`: la clave `anon`/publishable de Supabase.
   - `VITE_API_URL`: la URL de Render, por ejemplo
     `https://pcapanalyzer-api.onrender.com` (sin `/` final).
4. Despliega y copia la URL gratuita `https://<tu-app>.vercel.app`.
5. Vuelve a Render y añade esa URL a `CORS_ORIGINS`. Si conservas el acceso de
   desarrollo local, sepárala con una coma:
   `http://localhost:5173,https://<tu-app>.vercel.app`
6. En Supabase, abre **Authentication → URL Configuration** y establece la URL
   de Vercel como **Site URL** y como URL de redirección permitida.
7. Entra en la URL de Vercel, crea una cuenta de prueba, inicia sesión y prueba
   una captura pequeña. Verifica además `/health` en la API.

Si cambias `VITE_API_URL` o las URLs permitidas de Supabase, vuelve a desplegar
el frontend para que la configuración quede incluida en el bundle.

## Límites de esta beta

- Vercel proporciona un subdominio gratuito; no hace falta comprar un dominio
  para probar. GitHub Pages no es adecuado para esta configuración porque la
  API FastAPI y el worker no pueden ejecutarse allí.
- El primer acceso después de un periodo sin actividad puede tardar porque el
  backend gratuito de Render se suspende.
- La aplicación ya separa usuarios por espacios de trabajo, pero aún no hay
  pagos, gestión de suscripciones, planes, cuotas distintas por plan ni soporte
  comercial. Los límites actuales son compartidos/configurados por el servicio.
- No anuncies un SLA ni uses capturas sensibles de clientes reales hasta revisar
  el plan de alojamiento, la retención y borrado, el SMTP, las políticas de
  privacidad y las obligaciones legales aplicables.
