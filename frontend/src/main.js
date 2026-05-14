import Vue from 'vue';
import axios from 'axios';
import VueCookies from 'vue-cookies'
import BootstrapVue from 'bootstrap-vue'
import VueClipboard from 'vue-clipboard2'
import Notifications from 'vue-notification'
import VueGoodTablePlugin from 'vue-good-table'

Vue.use(VueCookies)
Vue.use(VueClipboard)
Vue.use(BootstrapVue)
Vue.use(Notifications)
Vue.use(VueGoodTablePlugin)

var axios_cfg = function(url, data='', type='form') {
  if (data == '') {
    return {
      method: 'get',
      url: url
    };
  } else if (type == 'form') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    };
  } else if (type == 'file') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'multipart/form-data' }
    };
   } else if (type == 'json') {
    return {
      method: 'post',
      url: url,
      data: data,
      headers: { 'Content-Type': 'application/json' }
    };
  }
};

new Vue({
  el: '#app',
  data: {
    columns: [
      {
        label: '名称',
        field: 'Identity',
        // filterable: true,
      },
      {
        label: '账号状态',
        field: 'AccountStatus',
        filterable: true,
      },
      {
        label: '活跃连接数',
        field: 'Connections',
        filterable: true,
      },
      {
        label: '过期时间',
        field: 'ExpirationDate',
        type: 'date',
        dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
        dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
        formatFn: function (value) {
          return value != "" ? value : ""
        }
      },
      {
        label: '吊销时间',
        field: 'RevocationDate',
        type: 'date',
        dateInputFormat: 'yyyy-MM-dd HH:mm:ss',
        dateOutputFormat: 'yyyy-MM-dd HH:mm:ss',
        formatFn: function (value) {
          return value != "" ? value : ""
        }
      },
      {
        label: '操作',
        field: 'actions',
        sortable: false,
        tdClass: 'text-right',
        globalSearchDisabled: true,
      },
    ],
    rows: [],
    actions: [
      {
        name: 'u-change-password',
        label: '修改密码',
        class: 'btn-warning',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ['passwdAuth'],
      },
      {
        name: 'u-revoke',
        label: '吊销',
        class: 'btn-warning',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-delete',
        label: '删除',
        class: 'btn-danger',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-delete',
        label: '删除',
        class: 'btn-danger',
        showWhenStatus: 'Expired',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-rotate',
        label: '轮换证书',
        class: 'btn-warning',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-rotate',
        label: '轮换证书',
        class: 'btn-warning',
        showWhenStatus: 'Expired',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      {
        name: 'u-unrevoke',
        label: '恢复',
        class: 'btn-primary',
        showWhenStatus: 'Revoked',
        showForServerRole: ['master'],
        showForModule: ["core"],
      },
      // {
      //   name: 'u-show-config',
      //   label: 'Show config',
      //   class: 'btn-primary',
      //   showWhenStatus: 'Active',
      //   showForServerRole: ['master', 'slave'],
      //   showForModule: ["core"],
      // },
      {
        name: 'u-download-config',
        label: '下载配置',
        class: 'btn-info',
        showWhenStatus: 'Active',
        showForServerRole: ['master', 'slave'],
        showForModule: ["core"],
      },
      {
        name: 'u-edit-ccd',
        label: '编辑路由',
        class: 'btn-primary',
        showWhenStatus: 'Active',
        showForServerRole: ['master'],
        showForModule: ["ccd"],
      },
      {
        name: 'u-edit-ccd',
        label: '查看路由',
        class: 'btn-primary',
        showWhenStatus: 'Active',
        showForServerRole: ['slave'],
        showForModule: ["ccd"],
      }
    ],
    filters: {
      hideRevoked: true,
    },
    serverRole: "master",
    lastSync: "unknown",
    modulesEnabled: [],
    auth: {
      enabled: false,
      authenticated: false,
      requiresTotp: false,
      username: '',
      loginUsername: 'admin',
      loginPassword: '',
      loginTotp: '',
      loginError: '',
      loginLoading: false,
    },
    u: {
      newUserName: '',
      newUserPassword: '',
      newUserCreateError: '',
      newPassword: '',
      passwordChangeStatus: '',
      passwordChangeMessage: '',
      rotateUserMessage: '',
      deleteUserMessage: '',
      modalNewUserVisible: false,
      modalShowConfigVisible: false,
      modalShowCcdVisible: false,
      modalChangePasswordVisible: false,
      modalRotateUserVisible: false,
      modalDeleteUserVisible: false,
      openvpnConfig: '',
      ccd: {
        Name: '',
        ClientAddress: '',
        CustomRoutes: []
      },
      newRoute: {},
      ccdApplyStatus: "",
      ccdApplyStatusMessage: "",
    }
  },
  watch: {
  },
  mounted: function () {
    this.filters.hideRevoked = this.$cookies.isKey('hideRevoked') ? (this.$cookies.get('hideRevoked') == "true") : false
    this.checkAuth();
  },
  created() {
    var _this = this;

    _this.$root.$on('u-revoke', function (msg) {
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/revoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: '用户 ' + _this.username + ' 已吊销', type: 'warn'})
      });
    })
    _this.$root.$on('u-unrevoke', function () {
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/unrevoke', data, 'form'))
      .then(function(response) {
        _this.getUserData();
        _this.$notify({title: '用户 ' + _this.username + ' 已恢复', type: 'success'})
      });
    })
    _this.$root.$on('u-rotate', function () {
      _this.u.modalRotateUserVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
    })
    _this.$root.$on('u-delete', function () {
      _this.u.modalDeleteUserVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
    })
    _this.$root.$on('u-show-config', function () {
      _this.u.modalShowConfigVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/config/show', data, 'form'))
      .then(function(response) {
        _this.u.openvpnConfig = response.data;
      });
    })
    _this.$root.$on('u-download-config', function () {
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/config/show', data, 'form'))
      .then(function(response) {
        const blob = new Blob([response.data], { type: 'text/plain' })
        const link = document.createElement('a')
        link.href = URL.createObjectURL(blob)
        link.download = _this.username + ".ovpn"
        link.click()
        URL.revokeObjectURL(link.href)
      }).catch(console.error);
    })
    _this.$root.$on('u-edit-ccd', function () {
      _this.u.modalShowCcdVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/ccd', data, 'form'))
      .then(function(response) {
        _this.u.ccd = response.data;
      });
    })
    _this.$root.$on('u-disconnect-user', function () {
      _this.u.modalShowCcdVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
      axios.request(axios_cfg('api/user/disconnect', data, 'form'))
      .then(function(response) {
        console.log(response.data);
      });
    })
    _this.$root.$on('u-change-password', function () {
      _this.u.modalChangePasswordVisible = true;
      var data = new URLSearchParams();
      data.append('username', _this.username);
    })
  },
  computed: {
    customAddressDynamic: function () {
      return this.u.ccd.ClientAddress == "dynamic"
    },
    ccdApplyStatusCssClass: function () {
        return this.u.ccdApplyStatus == 200 ? "alert-success" : "alert-danger"
    },
    passwordChangeStatusCssClass: function () {
      return this.u.passwordChangeStatus == 200 ? "alert-success" : "alert-danger"
    },
    userRotateStatusCssClass: function () {
      return this.u.roatateUserStatus == 200 ? "alert-success" : "alert-danger"
    },
    deleteUserStatusCssClass: function () {
      return this.u.deleteUserStatus == 200 ? "alert-success" : "alert-danger"
    },
    modalNewUserDisplay: function () {
      return this.u.modalNewUserVisible ? {display: 'flex'} : {}
    },
    modalShowConfigDisplay: function () {
      return this.u.modalShowConfigVisible ? {display: 'flex'} : {}
    },
    modalShowCcdDisplay: function () {
      return this.u.modalShowCcdVisible ? {display: 'flex'} : {}
    },
    modalChangePasswordDisplay: function () {
      return this.u.modalChangePasswordVisible ? {display: 'flex'} : {}
    },
    modalRotateUserDisplay: function () {
      return this.u.modalRotateUserVisible ? {display: 'flex'} : {}
    },
    modalDeleteUserDisplay: function () {
      return this.u.modalDeleteUserVisible ? {display: 'flex'} : {}
    },
    revokeFilterText: function() {
      return this.filters.hideRevoked ? "显示已吊销" : "隐藏已吊销"
    },
    filteredRows: function() {
      if (this.filters.hideRevoked) {
        return this.rows.filter(function(account) {
          return account.AccountStatus == "Active"
        });
      } else {
        return this.rows
      }
    }

  },
  methods: {
    rowStyleClassFn: function(row) {
      if (row.ConnectionStatus == 'Connected') {
        return 'connected-user'
      }
      if (row.AccountStatus == 'Revoked') {
        return 'revoked-user'
      }
      if (row.AccountStatus == 'Expired') {
        return 'expired-user'
      }
      return ''
    },
    rowActionFn: function(e) {
      this.username = e.target.dataset.username;
      this.$root.$emit(e.target.dataset.name);
    },
    loadAppData: function() {
      this.getUserData();
      this.getServerSetting();
    },
    checkAuth: function() {
      var _this = this;
      axios.request(axios_cfg('api/auth/status'))
        .then(function(response) {
          _this.auth.enabled = response.data.enabled;
          _this.auth.authenticated = !response.data.enabled || response.data.authenticated;
          _this.auth.requiresTotp = response.data.requiresTotp;
          _this.auth.username = response.data.username || '';

          if (_this.auth.authenticated) {
            _this.loadAppData();
          }
        })
        .catch(function() {
          _this.auth.enabled = true;
          _this.auth.authenticated = false;
          _this.auth.loginError = '无法获取登录状态';
        });
    },
    login: function() {
      var _this = this;
      _this.auth.loginLoading = true;
      _this.auth.loginError = '';

      axios.request(axios_cfg('api/auth/login', {
        username: _this.auth.loginUsername,
        password: _this.auth.loginPassword,
        totp: _this.auth.loginTotp,
      }, 'json'))
        .then(function(response) {
          _this.auth.enabled = response.data.enabled;
          _this.auth.authenticated = response.data.authenticated;
          _this.auth.requiresTotp = response.data.requiresTotp;
          _this.auth.username = response.data.username || '';
          _this.auth.loginPassword = '';
          _this.auth.loginTotp = '';
          _this.loadAppData();
        })
        .catch(function(error) {
          _this.auth.authenticated = false;
          if (error.response && error.response.data) {
            _this.auth.loginError = typeof error.response.data === 'string' ? error.response.data : (error.response.data.message || '登录失败');
          } else {
            _this.auth.loginError = '登录失败';
          }
        })
        .finally(function() {
          _this.auth.loginLoading = false;
        });
    },
    logout: function() {
      var _this = this;
      axios.request({
        method: 'post',
        url: 'api/auth/logout'
      }).finally(function() {
        _this.auth.authenticated = false;
        _this.auth.username = '';
        _this.rows = [];
        _this.modulesEnabled = [];
      });
    },
    getUserData: function() {
      var _this = this;
      axios.request(axios_cfg('api/users/list'))
        .then(function(response) {
          _this.rows = Array.isArray(response.data) ? response.data : [];
        });
    },

    getServerSetting: function() {
      var _this = this;
      axios.request(axios_cfg('api/server/settings'))
      .then(function(response) {
        _this.serverRole = response.data.serverRole;
        _this.modulesEnabled = response.data.modules;

        if (_this.serverRole == "slave") {
          axios.request(axios_cfg('api/sync/last/successful'))
          .then(function(response) {
            _this.lastSync =  response.data;
          });
        }
      });
    },

    createUser: function() {
      var _this = this;

      _this.u.newUserCreateError = "";

      var data = new URLSearchParams();
      data.append('username', _this.u.newUserName);
      data.append('password', _this.u.newUserPassword);

      _this.username = _this.u.newUserName;

      axios.request(axios_cfg('api/user/create', data, 'form'))
      .then(function(response) {
        _this.$notify({title: '用户 ' + _this.username + ' 创建成功', type: 'success'})
        _this.u.modalNewUserVisible = false;
        _this.u.newUserName = '';
        _this.u.newUserPassword = '';
        _this.getUserData();
      })
      .catch(function(error) {
        _this.u.newUserCreateError = error.response.data;
        _this.$notify({title: '用户 ' + _this.username + ' 创建失败', type: 'error'})

      });
    },

    ccdApply: function() {
      var _this = this;

      _this.u.ccdApplyStatus = "";
      _this.u.ccdApplyStatusMessage = "";

      axios.request(axios_cfg('api/user/ccd/apply', JSON.stringify(_this.u.ccd), 'json'))
      .then(function(response) {
        _this.u.ccdApplyStatus = 200;
        _this.u.ccdApplyStatusMessage = response.data;
        _this.$notify({title: '用户 ' + _this.username + ' 的 CCD 已应用', type: 'success'})
      })
      .catch(function(error) {
        _this.u.ccdApplyStatus = error.response.status;
        _this.u.ccdApplyStatusMessage = error.response.data;
        _this.$notify({title: '用户 ' + _this.username + ' 的 CCD 应用失败', type: 'error'})
      });
    },

    changeUserPassword: function(user) {
      var _this = this;

      _this.u.passwordChangeMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/change-password', data, 'form'))
        .then(function(response) {
          _this.u.passwordChangeStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalChangePasswordVisible = false;
          _this.$notify({title: '用户 ' + _this.username + ' 密码修改成功', type: 'success'})
        })
        .catch(function(error) {
          _this.u.passwordChangeStatus = error.response.status;
          _this.u.passwordChangeMessage = error.response.data.message;
          _this.$notify({title: '用户 ' + _this.username + ' 密码修改失败', type: 'error'})
        });
    },

    rotateUser: function(user) {
      var _this = this;

      _this.u.rotateUserMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);
      data.append('password', _this.u.newPassword);

      axios.request(axios_cfg('api/user/rotate', data, 'form'))
        .then(function(response) {
          _this.u.roatateUserStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalRotateUserVisible = false;
          _this.$notify({title: '用户 ' + _this.username + ' 的证书已轮换', type: 'success'})
        })
        .catch(function(error) {
          _this.u.roatateUserStatus = error.response.status;
          _this.u.rotateUserMessage = error.response.data.message;
          _this.$notify({title: '用户 ' + _this.username + ' 的证书轮换失败', type: 'error'})
        })
    },
    deleteUser: function(user) {
      var _this = this;

      _this.u.deleteUserMessage = "";

      var data = new URLSearchParams();
      data.append('username', user);

      axios.request(axios_cfg('api/user/delete', data, 'form'))
        .then(function(response) {
          _this.u.deleteUserStatus = 200;
          _this.u.newPassword = '';
          _this.getUserData();
          _this.u.modalDeleteUserVisible = false;
          _this.$notify({title: '用户 ' + _this.username + ' 已删除', type: 'success'})
        })
        .catch(function(error) {
          _this.u.deleteUserStatus = error.response.status;
          _this.u.deleteUserMessage = error.response.data.message;
          _this.$notify({title: '用户 ' + _this.username + ' 删除失败', type: 'error'})
        })
    },
  }

})
