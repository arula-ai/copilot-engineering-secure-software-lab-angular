import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () => import('./shared/components/home/home.component').then(m => m.HomeComponent)
  },
  // Vulnerable components
  {
    path: 'vulnerable/xss-bypass',
    loadComponent: () => import('./vulnerable/components/xss-bypass/xss-bypass.component').then(m => m.VulnerableXssBypassComponent)
  },
  {
    path: 'vulnerable/xss-innerhtml',
    loadComponent: () => import('./vulnerable/components/xss-innerhtml/xss-innerhtml.component').then(m => m.VulnerableXssInnerhtmlComponent)
  },
  {
    path: 'vulnerable/xss-interpolation',
    loadComponent: () => import('./vulnerable/components/xss-interpolation/xss-interpolation.component').then(m => m.VulnerableXssInterpolationComponent)
  },
  {
    path: 'vulnerable/auth',
    loadComponent: () => import('./vulnerable/components/login-form/login-form.component').then(m => m.VulnerableLoginFormComponent)
  },
  {
    path: 'vulnerable/csrf',
    loadComponent: () => import('./vulnerable/components/csrf-demo/csrf-demo.component').then(m => m.VulnerableCsrfDemoComponent)
  },
  {
    path: 'vulnerable/redirect',
    loadComponent: () => import('./vulnerable/components/redirect-handler/redirect-handler.component').then(m => m.VulnerableRedirectHandlerComponent)
  },
  {
    path: 'vulnerable/data-exposure',
    loadComponent: () => import('./vulnerable/components/data-exposure/data-exposure.component').then(m => m.VulnerableDataExposureComponent)
  },
  // Secure components
  {
    path: 'secure/xss-bypass',
    loadComponent: () => import('./secure/components/xss-bypass/xss-bypass.component').then(m => m.SecureXssBypassComponent)
  },
  {
    path: 'secure/xss-innerhtml',
    loadComponent: () => import('./secure/components/xss-innerhtml/xss-innerhtml.component').then(m => m.SecureXssInnerhtmlComponent)
  },
  {
    path: 'secure/xss-interpolation',
    loadComponent: () => import('./secure/components/xss-interpolation/xss-interpolation.component').then(m => m.SecureXssInterpolationComponent)
  },
  {
    path: 'secure/auth',
    loadComponent: () => import('./secure/components/login-form/login-form.component').then(m => m.SecureLoginFormComponent)
  },
  {
    path: 'secure/csrf',
    loadComponent: () => import('./secure/components/csrf-demo/csrf-demo.component').then(m => m.SecureCsrfDemoComponent)
  },
  {
    path: 'secure/redirect',
    loadComponent: () => import('./secure/components/redirect-handler/redirect-handler.component').then(m => m.SecureRedirectHandlerComponent)
  },
  {
    path: 'secure/data-exposure',
    loadComponent: () => import('./secure/components/data-exposure/data-exposure.component').then(m => m.SecureDataExposureComponent)
  },
  // Wildcard redirect
  {
    path: '**',
    redirectTo: ''
  }
];
