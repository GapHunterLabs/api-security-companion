# v0.2 API Security Companion Pro — plan de monetización (staging)

_Documentado: 2026-07-28. Sin código todavía — ver §5 antes de tocar
Marketplace._

## 1. Resumen general (vista rápida de los 8 plugins)

| # | Plugin | Plan actual | ¿Acción pendiente? | Próximo hito |
|---|---|---|---|---|
| 1 | Ansible Companion | **Freemium** (aplicado) | No — esperando aprobación JetBrains | Ninguno, solo esperar revisión |
| 2 | React Native Companion | Free (por diseño) | No | Ninguno — Fase 1 |
| 3 | Spreadsheet Companion | Free (por diseño) | No | Ninguno — Fase 1 |
| 4 | Nginx Companion | Free (por diseño) | No | Ninguno — Fase 1 |
| 5 | Theme Companion | Free (por diseño) | No | Ninguno — Fase 1 |
| 6 | Cert Companion | Free (por diseño) | No | Ninguno — Fase 1 |
| 7 | Highlight Companion | Free (por diseño, revisar más adelante) | No | Fase 3, oportunista |
| 8 | API Security Companion | Free (default; listing en moderación) | Sí, pero no en Marketplace todavía | Construir código Pro *antes* de aplicar a Freemium |

**Lectura de una línea:** 7 de 8 plugins están correctamente en Free por
decisión de producto, no por descuido. El único con una acción de
monetización real pendiente es API Security Companion, y esa acción es
*código*, no un clic en la web.

## 2. Por qué "Free" no es un estado a medio configurar

La pestaña Monetization de JetBrains Marketplace no tiene botón "Free".
Solo existen "Freemium" y "Paid", cada uno con su propio "Apply...". No
aplicar a ninguno de los dos ES el estado Free — confirmado directamente
en la UI real (Theme Companion, 2026-07-27). Por eso los 7 plugins listados
como "Free" arriba no tienen nada pendiente de marcar: es un estado
verificado, no un default abandonado.

## 3. Detalle por plugin

### Ansible Companion — Freemium (aplicado)
- **Ancla de precio:** producto registrado `PANSIBLECOMPANI`, ~$15-19/año
  sugerido según el ancla de mercado del nicho (competidores de Ansible
  tooling en el mismo rango).
- **Free:** encrypt/decrypt de Ansible Vault (1.1/AES256) desde el editor.
- **Pro (v0.2, en `plugin/future/v0.2-ansible-completion/`):** FQCN-aware
  completion (`ansible.builtin.*`) + Jinja2 syntax highlighting dentro de
  YAML. Implementado con `LicensingFacade` + `<product-descriptor
  optional="true">` — el patrón de referencia para cualquier Freemium
  futuro en este pipeline.
- **Estado real:** ya aplicado en Marketplace, pendiente de aprobación de
  JetBrains (proceso de revisión propio, no instantáneo). Sin acción
  nuestra pendiente — solo esperar.

### React Native Companion — Free
- **Por qué Free:** responde directamente a la queja "el companion de
  pago no funciona bien" en el nicho. Ser gratis y confiable ES la
  propuesta de valor completa. Un paywall propio contradice la razón de
  ser del plugin.
- **Revisar de nuevo cuándo:** nunca, salvo que surja evidencia de una
  función claramente "premium" separable sin romper esa promesa.

### Spreadsheet Companion — Free
- Mismo razonamiento que React Native Companion: utilidad pura (editor
  CSV/TSV + visor XLSX de solo lectura), sin infraestructura de licencia
  construida. Free indefinido, por diseño.

### Nginx Companion — Free
- Mismo razonamiento: syntax highlighting + completion de directivas
  nginx. Nicho utilitario, sin ancla de precio premium clara en la
  evidencia original. Free indefinido, por diseño.

### Theme Companion — Free
- Tema visual puro. No hay función "premium" lógica que separar de un
  tema (no es como completion o linting, donde sí hay un tier natural).
  Free indefinido, por diseño.

### Cert Companion — Free
- Utilitario de certificados/TLS. Mismo patrón: Free indefinido, por
  diseño, sin evidencia de demanda de un tier pago.

### Highlight Companion — Free (revisar en Fase 3, sin apuro)
- **Por qué Free hoy:** gutter icons de complejidad cognitiva por
  función/método — útil individualmente, pero sin evidencia todavía de
  que equipos paguen por una vista agregada.
- **Posible Pro futuro (no confirmado, no priorizado):** dashboard de
  complejidad a nivel de proyecto/equipo (tendencias, ranking de
  funciones más complejas del repo). Solo vale la pena si el uso real
  genera esa demanda — no construir en especulación.

### API Security Companion — Free (default), listing en moderación
- **Por qué es el candidato correcto para Freemium (Fase 2):** el
  comprador de seguridad empresarial sí paga — es la categoría entera que
  ataca el plugin (mismo espacio que Snyk, Qodana, ambos de pago).
- **Free (ya construido y en el código hoy):**
  - Detección de secretos hardcodeados (entropía de Shannon + patrones
    de nombre de variable).
  - HTTP inseguro / TLS trust-all.
  - 2 checks de OWASP API Top 10 en Java: Excessive Data Exposure, Mass
    Assignment.
  - 2 checks sobre especificaciones OpenAPI.
- **Pro propuesto (a construir, todavía NO existe en código):**
  - Soporte Kotlin para Excessive Data Exposure / Mass Assignment (hoy
    los anotadores de esos dos checks son Java-only).
  - Reglas de equipo compartidas vía archivo de políticas en VCS (hoy la
    configuración es `PersistentStateComponent` local, no compartible).
  - Cobertura ampliada de OWASP API Top 10: Broken Object Level
    Authorization (BOLA), Unrestricted Resource Consumption.
- **Regla dura aplicada aquí:** NO aplicar al botón "Freemium" en
  Marketplace hasta que el código Pro exista de verdad y sea
  verificable (build + test + verifyPlugin), igual que ya se corrigió en
  el caso de Ansible — aplicar antes de tener la función paga lista solo
  genera un checklist a medias sin nada real que ofrecer al comprador.
- **Estado real del listing (2026-07-28):** primer upload manual
  completado, listing creado, en cola de moderación de JetBrains
  (hasta 2 días hábiles). Esto solo habilita `publishPlugin` para
  versiones futuras — es independiente de la decisión de Monetization,
  que sigue en Free hasta que el Pro tier exista.

## 4. Plan de monetización general (3 fases)

**Fase 1 — ya decidida y estable.** React Native, Spreadsheet, Nginx,
Theme, Cert Companion se quedan en Free indefinidamente, por diseño. No
requieren revisión periódica salvo evidencia nueva y concreta de demanda
de un tier pago.

**Fase 2 — próxima acción de producto real (no de Marketplace).**
Construir el Pro tier de API Security Companion (Kotlin support para los
2 checks OWASP, reglas de equipo vía VCS, BOLA + Unrestricted Resource
Consumption). Solo después de que ese código exista, pase tests y
`verifyPlugin`, se aplica a Freemium en la web — un solo clic al final de
un trabajo de ingeniería real, no al principio.

**Fase 3 — oportunista, sin fecha.** Revisar Highlight Companion para un
posible Pro tier (dashboard de equipo) únicamente si el uso real genera
esa señal. No es una tarea en cola; es un "vigilar y esperar evidencia".

## 5. Próxima acción concreta sugerida

Ninguna acción de Marketplace pendiente hoy. La siguiente acción real es
de código: implementar dentro de este mismo directorio (`completion/`,
`detection/`, `detection-tests/`, `resources/`, siguiendo la estructura ya
usada en `plugin/future/v0.2-ansible-completion/`) el soporte Kotlin para
Excessive Data Exposure/Mass Assignment, las reglas de equipo vía VCS, y
los checks BOLA/Unrestricted Resource Consumption — recién ahí, con
build + test + `verifyPlugin` en verde, aplicar a Freemium en Marketplace.
