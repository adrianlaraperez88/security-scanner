import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TaskQueue } from '../../core/queue.js';
import {
  crawlPage,
  extractLinksAndFormsFromHtml,
  extractMenusFromHtml,
  parseSpaRoutesFromScript
} from '../../core/crawler.js';

test('TaskQueue: deduplicates, filters static asset extensions, and locks to domain', () => {
  const q = new TaskQueue('https://example.com');
  
  q.push('https://example.com/page1');
  q.push('https://example.com/page1'); // duplicate
  q.push('https://other.com/ext');     // off-domain
  q.push('/relative');                // relative
  q.push('/build/assets/app.js');     // static JS asset (filtered)
  q.push('/build/assets/app.css');    // static CSS asset (filtered)
  q.push('/fonts/inter.woff2');       // static font asset (filtered)
  q.push('/images/logo.png');         // static image asset (filtered)
  
  assert.equal(q.totalFound, 3); // '/', '/page1', '/relative'
  assert.equal(q.pending.length, 3); // '/', '/page1', '/relative'
});

test('crawlPage: extracts links from HTML', async () => {
  const mockFetch = async () => ({
    status: 200,
    text: `
      <html>
        <a href="/about">About</a>
        <img src="img.png">
        <script src="/js/app.js"></script>
        <a href="https://external.com">External</a>
      </html>
    `
  });

  const links = await crawlPage('https://example.com', mockFetch);
  assert.ok(links.includes('/about'));
  assert.ok(links.includes('img.png'));
  assert.ok(links.includes('/js/app.js'));
  assert.ok(links.includes('https://external.com'));
});

test('crawlPage: preserves ?query params, decodes &amp;, strips #fragment, and handles empty/missing res.text', async () => {
  const mockFetch = async () => ({
    status: 200,
    text: `
      <html>
        <a href="/search?q=test&amp;page=2#results">Search</a>
        <a href="?page=2#top">Next</a>
        <a href="?page=2#bottom">Next Duplicate</a>
        <a href="https://example.com/items?id=42#sec">Item</a>
        <a href="javascript:alert(1)">JS</a>
      </html>
    `
  });

  const links = await crawlPage('https://example.com', mockFetch);
  assert.ok(links.includes('/search?q=test&page=2'));
  assert.ok(links.includes('?page=2'));
  assert.equal(links.filter(l => l === '?page=2').length, 1);
  assert.ok(links.includes('https://example.com/items?id=42'));
  assert.equal(links.some(l => l.includes('#')), false);
  assert.equal(links.some(l => l.startsWith('javascript:')), false);

  const emptyLinks = await crawlPage('https://example.com', async () => ({ status: 200 }));
  assert.deepEqual(emptyLinks, []);
});

test('crawlPage & extractMenusFromHtml: discovers Yii + AngularJS dropdown menus, submenus, $routeProvider templateUrls, and view forms', async () => {
  const baseUrl = 'https://satprocess.com/broadbandAdmin/index.php/default/index';
  const indexHtml = `
    <!DOCTYPE html>
    <html ng-app="adminApp">
    <head>
      <script src="/broadbandAdmin/assets/jquery/jquery-1.11.2.min.js"></script>
      <script src="/broadbandAdmin/assets/bootstrap/js/bootstrap.min.js"></script>
      <script src="/broadbandAdmin/assets/admin/js/angular.min.js"></script>
      <script src="/broadbandAdmin/assets/admin/js/app.js?t=1795656590"></script>
    </head>
    <body ng-controller="MenuController">
      <nav class="navbar navbar-default">
        <ul class="nav navbar-nav">
          <li>
            <a href="#" ng-click="selectPage('dashboard', $event)">Dashboard</a>
          </li>
          <li>
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">Manage Tools</a>
            <ul class="dropdown-menu">
              <li><a href="#" ng-click="selectPage('configuration', $event)">Providers Configuration</a></li>
              <li><a href="#" ng-click="selectPage('zipcodemanager', $event)">Zip Code Manager</a></li>
              <li><a href="/access-manager">Access Manager</a></li>
              <!--<li><a href="#" ng-click="selectPage('access-manager', $event)">Access Manager 2</a></li>-->
              <li><a href="#" ng-click="selectPage('orderCreate', $event)">Manual BBND Order</a></li>
            </ul>
          </li>
          <li>
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">Reports</a>
            <ul class="dropdown-menu">
              <li><a href="#" ng-click="selectPage('orders', $event)">Broadband Orders</a></li>
              <li><a href="#" ng-click="selectPage('slingtvreport', $event)">SlingTv Reports</a></li>
            </ul>
          </li>
          <li>
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">External tools</a>
            <ul class="dropdown-menu">
              <li><a href="https://satprocess.com/mta/index.php/default/index" target="_blank">MTA Manager</a></li>
            </ul>
          </li>
          <li class="dropdown">
            <a href="#" class="dropdown-toggle" data-toggle="dropdown">Adrian Lara Perez</a>
            <ul class="dropdown-menu">
              <li><a href="/broadbandAdmin/index.php/site/logout">Logout</a></li>
            </ul>
          </li>
        </ul>
      </nav>
      <script>
        const environment = { baseUrl: '/broadbandAdmin/', environment: 'prod', isProd: true };
      </script>
    </body>
    </html>
  `;

  const appJs = `
    var adminApp = angular.module('adminApp', ['ngRoute']);
    var adminPath = environment.baseUrl;
    adminApp.config(['$routeProvider', function($routeProvider){
      $routeProvider.
        when('/dashboard', { templateUrl: adminPath + 'index.php/default/dashboard', controller: 'DashboardController' }).
        when('/configuration', { templateUrl: adminPath + 'index.php/configuration/index', controller: 'ConfigurationController' }).
        when('/zipcodemanager', { templateUrl: adminPath + 'index.php/zipcodemanager/index', controller: 'ZipCodeManagerController' }).
        when('/access-manager', { templateUrl: adminPath + 'index.php/skillgroupmanager/index', controller: 'SkillGroupManagerController' }).
        when('/orderCreate', { templateUrl: adminPath + 'index.php/OrderManage/orderCreate', controller: 'OrderCreateController' }).
        when('/orders', { templateUrl: adminPath + 'index.php/logreport/orders', controller: 'LogReportController' }).
        when('/slingtvreport', { templateUrl: adminPath + 'index.php/slingtvreport/index', controller: 'SlingTvReportController' }).
        when('/zipcodeupload', { templateUrl: adminPath + 'index.php/zipcodemanager/MassUpload', controller: 'ZipCodeManagerController' });
    }]);
  `;

  const orderCreateViewHtml = `
    <div class="panel">
      <h3>Create Manual Broadband Order</h3>
      <form id="manual-order-form" method="post" action="/broadbandAdmin/index.php/OrderManage/saveOrder">
        <input type="hidden" name="YII_CSRF_TOKEN" value="csrf123456" />
        <input type="text" ng-model="order.customerName" id="customer_name" />
        <select name="provider" ng-model="order.provider">
          <option value="att" selected>AT&amp;T</option>
          <option value="verizon">Verizon</option>
        </select>
        <textarea name="notes" ng-model="order.notes"></textarea>
        <button type="submit">Save Order</button>
      </form>
    </div>
  `;

  const mockFetch = async (url) => {
    if (url === baseUrl) {
      return { status: 200, url: baseUrl, text: indexHtml };
    }
    if (url.includes('/broadbandAdmin/assets/admin/js/app.js')) {
      return { status: 200, url, text: appJs };
    }
    if (url === 'https://satprocess.com/broadbandAdmin/index.php/OrderManage/orderCreate') {
      return { status: 200, url, text: orderCreateViewHtml };
    }
    return { status: 404, url, text: 'Not Found' };
  };

  const crawlRes = await crawlPage(baseUrl, mockFetch, { includeResponse: true });

  // 1. Verify menus & submenus extracted with resolved templateUrl and controller
  assert.ok(Array.isArray(crawlRes.menus));
  const configMenu = crawlRes.menus.find(m => m.parentMenu === 'Manage Tools' && m.label === 'Providers Configuration');
  assert.ok(configMenu, 'Expected Manage Tools -> Providers Configuration submenu');
  assert.equal(configMenu.kind, 'submenu');
  assert.equal(configMenu.controller, 'ConfigurationController');
  assert.equal(configMenu.url, 'https://satprocess.com/broadbandAdmin/index.php/configuration/index');

  const accessMenu = crawlRes.menus.find(m => m.parentMenu === 'Manage Tools' && m.label === 'Access Manager');
  assert.ok(accessMenu, 'Expected Manage Tools -> Access Manager submenu');
  assert.equal(accessMenu.url, 'https://satprocess.com/broadbandAdmin/index.php/skillgroupmanager/index');

  // Commented-out "Access Manager 2" must NOT be included
  assert.equal(crawlRes.menus.some(m => m.label === 'Access Manager 2'), false);

  // Unlinked $routeProvider route (/zipcodeupload) must be included under SPA Router ($routeProvider)
  const hiddenSpaRoute = crawlRes.menus.find(m => m.routeKey === 'zipcodeupload');
  assert.ok(hiddenSpaRoute, 'Expected unlinked $routeProvider route zipcodeupload');
  assert.equal(hiddenSpaRoute.kind, 'spa_route');
  assert.equal(hiddenSpaRoute.url, 'https://satprocess.com/broadbandAdmin/index.php/zipcodemanager/MassUpload');

  // External app link (/mta/) is classified as external_app in menus, and excluded from /broadbandAdmin/ crawl links
  const mtaMenu = crawlRes.menus.find(m => m.label === 'MTA Manager');
  assert.ok(mtaMenu);
  assert.equal(mtaMenu.kind, 'external_app');
  assert.equal(crawlRes.links.some(l => l.includes('/mta/')), false);

  // Logout link is classified as logout in menus and excluded from crawl links
  const logoutMenu = crawlRes.menus.find(m => m.label === 'Logout');
  assert.ok(logoutMenu);
  assert.equal(logoutMenu.kind, 'logout');
  assert.equal(crawlRes.links.some(l => l.includes('logout')), false);

  // 2. Verify crawling the discovered submenu view extracts its form, ng-model inputs, and YII_CSRF_TOKEN
  const orderViewCrawl = await crawlPage(
    'https://satprocess.com/broadbandAdmin/index.php/OrderManage/orderCreate',
    mockFetch,
    { includeResponse: true, discoverAppScripts: false }
  );
  assert.equal(orderViewCrawl.forms.length, 1);
  const orderForm = orderViewCrawl.forms[0];
  assert.equal(orderForm.formName, 'Create Manual Broadband Order');
  assert.equal(orderForm.method, 'POST');
  assert.equal(orderForm.csrfField, 'YII_CSRF_TOKEN');
  assert.deepEqual(
    orderForm.fields.map(f => f.name),
    ['customerName', 'provider', 'notes']
  );
});
