# 09. Consideraciones de Seguridad y Cumplimiento Normativo Bancario

## 1. Alineación con Estándares Internacionales

### 1.1 OWASP ASVS v4.0 (Application Security Verification Standard - Nivel 3)
La plataforma se adhiere al Nivel 3 de ASVS (reservado para aplicaciones bancarias y de infraestructura crítica):
- **V1 - Arquitectura**: Modelado de amenazas formal (STRIDE) y principio de defensa en profundidad.
- **V2 - Autenticación**: Almacenamiento de contraseñas con Bcrypt con factor de costo 12+, soporte mandatorio de MFA (TOTP RFC 6238) y política estricta de bloqueo tras 5 intentos erróneos.
- **V3 - Control de Acceso**: Control de acceso basado en roles (RBAC) verificado en cada endpoint mediante inyección de dependencias (`Depends`) en FastAPI. Prohibición de referencias directas inseguras a objetos (BOLA/IDOR) validando pertenencia de tenant.
- **V5 - Validación y Codificación**: Tipado estricto con Pydantic v2 en todas las entradas. Sanitización de URLs y parámetros para mitigar Server-Side Request Forgery (SSRF) en las llamadas del analizador a servidores externos.

---

## 2. Cifrado y Criptografía

### 2.1 Cifrado en Tránsito (In-Transit)
- Comunicación externa e interna forzada mediante **TLS 1.3** con suites de cifrado seguras (`TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`).
- Cabecera **HSTS (HTTP Strict Transport Security)** obligatoria con `max-age=63072000; includeSubDomains; preload`.
- Certificados TLS renovados automáticamente mediante Let's Encrypt o la Autoridad Certificadora (PKI) corporativa del banco.

### 2.2 Cifrado en Reposo (At-Rest)
- Base de datos PostgreSQL configurada con cifrado transparente a nivel de disco (**TDE / LUKS** con AES-256-XTS).
- Campos sensibles (secretos MFA, metadatos confidenciales de cuentahabientes) cifrados a nivel de columna con `pgcrypto` (`pgp_sym_encrypt`) utilizando llaves maestras custodiadas en **HashiCorp Vault**.
- Evidencias digitales y volcados forenses almacenados en buckets de objetos cifrados con llaves administradas por el cliente (KMS con rotación anual).

---

## 3. Gestión de Secretos y Llaves Criptográficas (HashiCorp Vault)
- Cero contraseñas o API keys en archivos de configuración, variables de entorno planas o repositorios Git.
- El backend FastAPI se autentica contra HashiCorp Vault al arrancar mediante el método **Kubernetes Service Account Token**.
- Vault genera credenciales de base de datos dinámicas con un tiempo de vida (TTL) de 1 hora, revocándolas automáticamente si un pod se destruye.

---

## 4. Pistas de Auditoría Inmutables (Tamper-Evident Audit Trail - PCI-DSS Req 10)
Cada acción administrativa y de investigación forense genera un registro en la tabla `audit_logs` con encadenamiento criptográfico:
$$\text{record\_hash}_n = \text{HMAC-SHA256}\left(\text{previous\_hash}_{n-1} \,\|\, \text{actor\_id} \,\|\, \text{action} \,\|\, \text{timestamp} \,\|\, \text{details}\right)$$

Cualquier intento de alteración o borrado de una fila en la base de datos rompe la cadena de hashes, disparando una alerta crítica inmediata hacia el SIEM bancario.

---

## 5. Matriz de Cumplimiento Normativo Bancario

| Requisito Normativo | Control Implementado en AegisBank |
| :--- | :--- |
| **PCI-DSS v4.0 Req 3** | Cero almacenamiento de números de tarjeta completos (PAN) ni códigos de seguridad (CVV/CVC) en la base de datos de incidentes. Enmascaramiento y anonimización de artefactos de correo. |
| **PCI-DSS v4.0 Req 6** | Ciclo de vida de desarrollo seguro (SDLC), SAST/DAST en CI/CD y parches de seguridad aplicados en menos de 30 días. |
| **PCI-DSS v4.0 Req 8** | Identificación única de usuarios, contraseñas robustas, bloqueo por 15 minutos tras 5 fallos y MFA obligatorio para administradores del SOC. |
| **PCI-DSS v4.0 Req 10** | Registro detallado y sincronizado por NTP de todos los accesos a datos forenses y retención mínima de 12 meses (3 meses inmediatamente accesibles). |
| **ISO/IEC 27001:2022 A.5.24** | Procedimientos documentados y automatizados para la gestión de incidentes de seguridad de la información. |
| **ISO/IEC 27001:2022 A.8.16** | Monitoreo continuo de actividades y correlación de eventos de suplantación. |
| **GDPR / Ley de Protección de Datos** | Minimización de datos: los nombres y correos de cuentahabientes son enmascarados con algoritmos de hashing determinista salteado antes del almacenamiento. |

