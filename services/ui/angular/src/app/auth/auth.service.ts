import { Injectable } from '@angular/core';
import {of, Observable} from 'rxjs';
import {catchError, map} from 'rxjs/operators';
import { Router } from '@angular/router';
import { HttpClient } from '@angular/common/http';
import {Registration} from './registration.interface';
import { environment } from '../../environments/environment';

interface User {
  _id: string;
  username: string;
}

interface LoginResponse {
  token: string;
  user: User;
}

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  redirectUrl: string;

  private endpoint = `${environment.apiUrl}/auth`;
  private loggedInUser: User;

  private get token(): string {
    return localStorage.getItem('access_token');
  }

  private set token(token: string | null) {
    if (!token) {
      localStorage.removeItem('access_token');
    } else {
      localStorage.setItem('access_token', token);
    }
  }

  constructor(
    private router: Router,
    private http: HttpClient
  ) {}

  async isLoggedIn(): Promise<boolean> {
    if (!this.token) {
      return false;
    }
    if (this.loggedInUser && this.loggedInUser._id) {
      return true;
    }

    const user = await this.http.get<User>(`${this.endpoint}/loggedin`).pipe(
      catchError((err, caught) => of(null))
    ).toPromise();
    if (user && user._id) {
      this.loggedInUser = user;
      return true;
    }

    this.token = null;
    this.loggedInUser = null;
    return false;
  }

  getLoggedInUser(): User {
    return this.loggedInUser;
  }

  validateUrl(url: string): boolean {
    const allowedUrls = [
      `${this.endpoint}/login`,
      `${this.endpoint}/register`,
      `${this.endpoint}/logout`,
      `${this.endpoint}/loggedin`
    ];
    return allowedUrls.includes(url);
  }

  login(username: string, password: string): Observable<boolean> {
    this.token = null;
    const url = `${this.endpoint}/login`;
    if (!this.validateUrl(url)) {
      throw new Error('Invalid URL');
    }
    return this.http.post<LoginResponse>(url, {username, password})
      .pipe(map(({ token, user }) => {
        this.token = token;
        this.loggedInUser = user;
        return !!token;
      }));
  }

  register(registration: Registration): Observable<boolean> {
    const url = `${this.endpoint}/register`;
    if (!this.validateUrl(url)) {
      throw new Error('Invalid URL');
    }
    return this.http.post<LoginResponse>(url, registration)
      .pipe(map( ({ token, user }) => {
        this.token = token;
        this.loggedInUser = user;
        return !!token;
      }));
  }

  logout() {
    this.token = null;
    this.loggedInUser = null;
    const url = `${this.endpoint}/logout`;
    if (!this.validateUrl(url)) {
      throw new Error('Invalid URL');
    }
    this.http.post<void>(url, {});
    this.router.navigate(['/login']);
  }
}
