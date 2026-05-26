import { test } from 'node:test';
import assert from 'node:assert/strict';
import { fingerprint } from '../../core/fingerprint.js';

test('Fingerprint: accurately identifies WordPress even with PHP/Nginx headers', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'server': 'nginx/1.18.0',
      'x-powered-by': 'PHP/7.4.3',
      'x-generator': 'WordPress 6.4.2'
    },
    text: `
      <html>
        <head>
          <link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css">
        </head>
        <body>
          <h1>WordPress Test</h1>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://wp.example.com', mockFetch);
  assert.equal(res.primary, 'wordpress');
  assert.ok(res.confidence >= 5);
  assert.ok(res.stack.some(t => t.tech === 'php'));
  assert.ok(res.stack.some(t => t.tech === 'nginx'));
});

test('Fingerprint: identifies Laravel through CSRF token and Livewire signals', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'laravel_session=abc; XSRF-TOKEN=xyz',
      'server': 'Apache'
    },
    text: `
      <html>
        <head>
          <meta name="csrf-token" content="csrf-value">
        </head>
        <body>
          <form><input type="hidden" name="_token" value="csrf"></form>
          <div wire:id="123" wire:initial-data="{}">Livewire component</div>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://laravel.example.com', mockFetch);
  assert.equal(res.primary, 'laravel');
  assert.ok(res.stack.some(t => t.tech === 'laravel'));
});

test('Fingerprint: identifies Symfony through toolbar and cookies', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'symfony=xyz',
      'server': 'nginx'
    },
    text: `
      <html>
        <body>
          <div id="sf-toolbar">Symfony Debug Toolbar</div>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://symfony.example.com', mockFetch);
  assert.equal(res.primary, 'symfony');
});

test('Fingerprint: identifies Django through csrfmiddlewaretoken', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'set-cookie': 'csrftoken=abc; sessionid=def'
    },
    text: `
      <html>
        <body>
          <input type="hidden" name="csrfmiddlewaretoken" value="token">
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://django.example.com', mockFetch);
  assert.equal(res.primary, 'django');
});

test('Fingerprint: identifies Spring Boot through Whitelabel page text', async () => {
  const mockFetch = async () => ({
    status: 500,
    headers: {},
    text: `
      <html>
        <body>
          <h1>Whitelabel Error Page</h1>
          <p>This application has no explicit mapping for /error</p>
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://spring.example.com', mockFetch);
  assert.equal(res.primary, 'spring');
});

test('Fingerprint: identifies ASP.NET through ViewState and RequestVerificationToken', async () => {
  const mockFetch = async () => ({
    status: 200,
    headers: {
      'x-aspnet-version': '4.0.30319'
    },
    text: `
      <html>
        <body>
          <input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="foo">
        </body>
      </html>
    `
  });

  const res = await fingerprint('https://dotnet.example.com', mockFetch);
  assert.equal(res.primary, 'aspnet');
});
