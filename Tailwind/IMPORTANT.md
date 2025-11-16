# **Tailwind CSS Integration Guide for Django (with Node-based Auto-Build System)**

This guide combines the full setup process (Node, Tailwind, PostCSS, Typography, file structure) with the usage instructions for integrating Tailwind into your Django project. It also reflects your system that scans all Django templates for Tailwind classes and auto-builds the `tailwind.css` file.

---

# **1. Install and Initialize Your Tailwind Build System**

This section sets up the Node-based Tailwind environment that runs independently from Django but generates the CSS your Django app uses.

---

## **1. Install Node.js and npm**

You must have Node and npm installed.

```bash
node -v
npm -v
```

If either command fails, install from the official Node website.

---

## **2. Create a Workspace Directory for Tailwind**

Inside your Django project root, create a dedicated folder. This keeps all Tailwind/Node files isolated from the backend.

```bash
mkdir Tailwind
cd Tailwind
```

---

## **3. Initialize npm**

Creates the `package.json` file that tracks all dependencies.

```bash
npm init -y
```

---

## **4. Install Tailwind CSS, PostCSS, Autoprefixer, and Plugins**

Install the core packages:

```bash
npm install tailwindcss postcss autoprefixer
```

Install Typography plugin (you’re using it):

```bash
npm install @tailwindcss/typography
```

Optionally install Tailwind CLI globally:

```bash
npm install -g tailwindcss
```

---

## **5. Generate `tailwind.config.js`**

This file defines your Tailwind setup.

```bash
npx tailwindcss init
```

Replace the generated config with your project-specific version:

```javascript
/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './templates/**/*.html',
    './static/**/*.js',
    '**/templates/**/*.html',
    '**/static/**/*.js',
    '../**/templates/**/**/*.html',
    '../**/templates/**/*.html',
    '../**/templates/*.html',
    '../static/**/*.js',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#f0f9ff',
          100: '#e0f2fe',
          500: '#0ea5e9',
          600: '#0284c7',
          700: '#0369a1',
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
};
```

This ensures Tailwind scans *every possible template and JS location* in your Django project.

---

## **6. Create the CSS Entry File**

Make a folder for source CSS:

```bash
mkdir src
touch src/styles.css
```

Add Tailwind layers:

```css
@tailwind base;
@tailwind components;
@tailwind utilities;
```

---

## **7. Configure PostCSS**

Create `postcss.config.js`:

```javascript
module.exports = {
  plugins: {
    tailwindcss: {},
    autoprefixer: {},
  },
};
```

---

## **8. Build Tailwind Output CSS**

Your Node watcher system automatically compiles all used classes into one CSS file. Run:

```bash
npx tailwindcss -i ./src/styles.css -o ../static/css/tailwind.css --watch
```

Meaning:

* Input: `src/styles.css`
* Output: `../static/css/tailwind.css` (Django consumes this)
* Watch mode: updates instantly when you add new classes to templates

Create directory if needed:

```bash
mkdir -p ../static/css
```

---

# **2. Integrate the Generated Tailwind CSS into Your Django Project**

Now that your Node/Tailwind system is running, this section covers what Django needs for everything to work correctly.

---

## **1. Configure Static Files in Django**

In `settings.py`:

```python
STATIC_URL = '/static/'

STATICFILES_DIRS = [
    BASE_DIR / "static",
    # Add any app-specific static paths if needed
]
```

Make sure you have:

```
project_root/static/css/tailwind.css   <-- this is the generated file
```

---

## **2. Include Tailwind in Your Templates**

Inside your base HTML template:

```html
<link href="{% static 'css/tailwind.css' %}" rel="stylesheet">
```

Typography plugin works automatically via:

```html
<div class="prose">
    {{ rich_text|safe }}
</div>
```

---

## **3. Verify Template Paths in `tailwind.config.js`**

Tailwind will not generate styles unless the file paths are correct.

Your config includes paths that cover:

* global template directories
* per-app template folders
* static JS files anywhere in the project

This ensures your watcher never misses a class.

---

## **4. Deployment Notes**

When deploying:

```bash
python manage.py collectstatic
```

Your generated `tailwind.css` becomes part of your static files bundle.

You do **not** deploy Node or npm. Only the final CSS file ships to production.

---

# **3. How Your Automated Class Scanner Works (Optional Section)**

Your Node system constantly:

1. Monitors all Django templates and JS files
2. Detects Tailwind class names
3. Rebuilds `tailwind.css` accordingly
4. Writes updates instantly

This gives you:

* Clean CSS
* No unused classes bloating the output
* Instant reflection of UI changes
* Compatibility with Typography plugin and any custom theme extensions
