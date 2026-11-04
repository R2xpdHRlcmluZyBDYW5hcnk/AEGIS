import { Component, HostListener, OnInit, ChangeDetectionStrategy } from '@angular/core';
import { CommonModule } from '@angular/common';
import { Api, ConsoleState, Page, pages } from './core';
import { OverviewComponent } from './pages/overview.component';
import { EventsComponent } from './pages/events.component';
import { RulesComponent } from './pages/rules.component';
import { SystemComponent } from './pages/system.component';
import { DetailsComponent } from './details.component';
import { ModalComponent } from './modal.component';
@Component({changeDetection:ChangeDetectionStrategy.Eager,selector:'ndr-root',standalone:true,imports:[CommonModule,OverviewComponent,EventsComponent,RulesComponent,SystemComponent,DetailsComponent,ModalComponent],template:`
 <a class="skip-link" href="#main">跳转到主要内容</a><div class="workspace"><aside class="sidebar"><a class="brand" href="#overview" (click)="$event.preventDefault();state.navigate('overview')"><img class="brand-icon" src="/favicon.svg" alt="AEGIS"></a>
 <nav aria-label="主导航"><button *ngFor="let item of pages" [attr.data-page]="item.id" [class.active]="state.page()===item.id" [attr.aria-current]="state.page()===item.id?'page':null" (click)="state.navigate(item.id)"><span class="nav-label">{{item.title}}</span><span class="nav-arrow">↗</span></button></nav>
 <div class="sidebar-bottom"><a href="/metrics" target="_blank" rel="noopener">查看 Prometheus 指标 ↗</a></div></aside>
 <div class="main-area"><header class="app-header"><div class="header-actions"><button class="quiet" (click)="api.logout()">退出登录 ↗</button></div></header>
 <div class="content-viewport"><main id="main" tabindex="-1" (wheel)="state.cancelScrollRestore()" (pointerdown)="state.cancelScrollRestore()" (touchstart)="state.cancelScrollRestore()" (keydown)="state.scrollKey($event)"><div class="page-heading"><div><h1>{{current.title}}</h1></div></div>
 <ndr-overview animate.enter="page-enter" *ngIf="state.page()==='overview'"/><ndr-events animate.enter="page-enter" *ngIf="state.page()==='alerts'" mode="alerts"/><ndr-events animate.enter="page-enter" *ngIf="state.page()==='hunt'" mode="hunt"/><ndr-events animate.enter="page-enter" *ngIf="state.page()==='drops'" mode="drops"/><ndr-rules animate.enter="page-enter" *ngIf="state.page()==='rules'"/><ndr-system animate.enter="page-enter" *ngIf="state.page()==='system'"/>
 </main></div></div></div>
 <ndr-details/><ndr-modal *ngIf="state.confirmation() as c" [title]="c.title" (closed)="state.answer(false)"><p>{{c.message}}</p><footer class="modal-actions"><button class="quiet" (click)="state.answer(false)">取消</button><button class="danger-button" (click)="state.answer(true)">确认</button></footer></ndr-modal>
 <div class="toast" animate.enter="notice-enter" role="status" aria-live="polite" *ngIf="state.notice()">{{state.notice()}}<button class="icon-button" aria-label="关闭提示" (click)="state.notice.set('')">✕</button></div>
`})
export class AppComponent implements OnInit {
 pages=pages;
 constructor(public state:ConsoleState,public api:Api){}
 get current(){return pages.find(p=>p.id===this.state.page())!;}
 ngOnInit():void{this.hash();}
 @HostListener('window:hashchange') hash():void{const hash=location.hash.slice(1);this.state.navigate(pages.some(p=>p.id===hash)?hash as Page:'overview');}
}
