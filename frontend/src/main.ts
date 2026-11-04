import { provideZoneChangeDetection } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient } from '@angular/common/http';
import { AppComponent } from './app/app.component';
bootstrapApplication(AppComponent,{providers:[provideHttpClient(),provideZoneChangeDetection()]}).catch(error=>{console.error(error);document.body.textContent='控制台加载失败，请刷新页面。';});
