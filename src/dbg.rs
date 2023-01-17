use crate::helper::DynError;
use nix::{
    libc::{personality, user_regs_struct},
    sys::{
        personality::{self, Persona},
        ptrace,
        wait::{waitpid, WaitStatus},
    },
    unistd::{execvp, fork, ForkResult, Pid},
};
use std::{
    ffi::{c_void, CString},
    ops::Not,
};

pub struct DbgInfo {
    pid: Pid,
    brk_addr: Option<*mut c_void>,
    brk_val: i64,     // ブレークポイントを設定したメモリのもとの値
    filename: String, // 実行ファイル
}

// TがRunningのときは子プロセス実行中
// NotRunningのときは子プロセスを実行していない
pub struct ZDbg<T> {
    info: Box<DbgInfo>,
    _state: T,
}

// 以下の2つはサイズが0なので実行時にメモリを消費しない。幽霊型
pub struct Running;
pub struct NotRunning;

pub enum State {
    Running(ZDbg<Running>),
    NotRunning(ZDbg<NotRunning>),
    Exit,
}

fn do_help() {
    println!(
        r#"コマンド一覧
break(b) 0x8000 : ブレークポイントを0x8000番地に設定
run(r)          : プログラムを実行
continue(c)     : プログラムを再開
stepi(s)        : 機械語レベルで1ステップ実行
registers(regs) : レジスタを表示
exit            : 終了
help            : このヘルプを表示
"#
    );
}

impl<T> ZDbg<T> {
    fn set_break_addr(&mut self, cmd: &[&str]) -> bool {
        if self.info.brk_addr.is_some() {
            eprintln!(
                "<<ブレークポイントは設定済みです : Addr = {:p}>>",
                self.info.brk_addr.unwrap()
            );
            false
        } else if let Some(addr) = get_break_addr(cmd) {
            self.info.brk_addr = Some(addr); // ブレークポイントのアドレスを設定
            true
        } else {
            false
        }
    }

    fn do_cmd_common(&self, cmd: &[&str]) {
        match cmd[0] {
            "help" | "h" => do_help(),
            _ => (),
        }
    }
}

impl ZDbg<NotRunning> {
    pub fn new(filename: String) -> Self {
        ZDbg {
            info: Box::new(DbgInfo {
                pid: Pid::from_raw(0),
                brk_addr: None,
                brk_val: 0,
                filename,
            }),
            _state: NotRunning,
        }
    }

    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, DynError> {
        if cmd.is_empty() {
            return Ok(State::NotRunning(self));
        }

        match cmd[0] {
            "run" | "r" => return self.do_run(cmd),
            "break" | "b" => {
                self.do_break(cmd);
            }
            "exit" => return Ok(State::Exit),
            "continue" | "c" | "stepi" | "s" | "registers" | "regs" => {
                eprintln!("<<ターゲットを実行していません。runで実行してください>>")
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::NotRunning(self))
    }

    fn do_break(&mut self, cmd: &[&str]) -> bool {
        self.set_break_addr(cmd)
    }

    // 参照ではなくselfをmoveしている
    fn do_run(mut self, cmd: &[&str]) -> Result<State, DynError> {
        // execvpのためにCStringに変換が必要
        let args: Vec<CString> = cmd.iter().map(|s| CString::new(*s).unwrap()).collect();

        match unsafe { fork()? } {
            ForkResult::Child => {
                // ASLRを無効化している。セキュリティのためにメモリの配置をランダムにする機能だが、デバッガを使う際には不便なため
                let p = personality::get().unwrap();
                personality::set(p | Persona::ADDR_NO_RANDOMIZE).unwrap();
                // これで自身をトレース対象にしている。この後execするとプロセスが即座に停止するそうだ
                ptrace::traceme().unwrap();
                // 子プロセスで渡されたコマンドを実行する
                execvp(&CString::new(self.info.filename.as_str()).unwrap(), &args).unwrap();
                unreachable!();
            }
            ForkResult::Parent { child, .. } => match waitpid(child, None)? {
                WaitStatus::Stopped(..) => {
                    println!("<<子プロセスの実行に成功しました : PID = {child}>>");
                    self.info.pid = child;
                    let mut dbg = ZDbg::<Running> {
                        info: self.info,
                        _state: Running,
                    };
                    dbg.set_break()?; // bp設定。これはプロセスの実行中にしか行えない
                    dbg.do_continue()
                }
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    Err("子プロセスの実行に失敗しました".into())
                }
                _ => Err("プロセスが不正な状態です".into()),
            },
        }
    }
}

impl ZDbg<Running> {
    fn set_break(&mut self) -> Result<(), DynError> {
        // すでにブレークポイントがはられているならその値を取得。なかったら帰る
        let addr = if let Some(addr) = self.info.brk_addr {
            addr
        } else {
            return Ok(());
        };

        // 対象のアドレスのメモリ上の値を取得。結果はi64で返る
        let val = match ptrace::read(self.info.pid, addr) {
            Ok(val) => val,
            Err(e) => {
                eprintln!("<<ptrace::readに失敗: {e}, addr = {:p}>>", addr);
                return Ok(());
            }
        };

        // メモリ上の値を表示する補助関数
        fn print_val(addr: usize, val: i64) {
            print!("{:x}:", addr);
            for n in (0..8).map(|n| ((val >> (n * 8)) & 0xff) as u8) {
                print!(" {:x}", n);
            }
        }

        println!("<<以下のようにメモリを書き換えます>>");
        print!("<<before: ");
        print_val(addr as usize, val);
        println!(">>");

        // val & !0xffで、下位8bitがクリアされて、そこに0xccとorを取ると0xccが下位8bitになるというわけ
        // x86_64ではリトルエンディアンなので下位ビットを置き換えているが、ビッグエンディアンだったらば逆にする必要がある
        let val_int3 = (val & !0xff) | 0xcc; //  "int 3" に設定
        print!("<<after : ");
        print_val(addr as usize, val_int3);
        println!(">>");

        match unsafe { ptrace::write(self.info.pid, addr, val_int3 as *mut c_void) } {
            Ok(_) => {
                self.info.brk_addr = Some(addr);
                self.info.brk_val = val; // もとの値を保持
            }
            Err(e) => {
                eprintln!("<<ptrace::writeに失敗 : {e}, addr = {:p}>>", addr);
            }
        }

        Ok(())
    }

    fn wait_child(self) -> Result<State, DynError> {
        match waitpid(self.info.pid, None)? {
            WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                println!("<<子プロセスが終了しました>>");
                let not_run = ZDbg::<NotRunning> {
                    info: self.info,
                    _state: NotRunning,
                };
                Ok(State::NotRunning(not_run))
            }
            WaitStatus::Stopped(..) => {
                let mut regs = ptrace::getregs(self.info.pid)?;
                if Some((regs.rip - 1) as *mut c_void) == self.info.brk_addr {
                    unsafe {
                        // 書き換えたアドレスをもとに戻す
                        ptrace::write(
                            self.info.pid,
                            self.info.brk_addr.unwrap(),
                            self.info.brk_val as *mut c_void,
                        )?
                    };

                    // bpで停止したアドレスから1戻す。これはプロセスが止まった時のプログラムカウンタが一つ後ろを指しているので、
                    // 正しく再開するためには-1する必要がある
                    regs.rip -= 1;
                    ptrace::setregs(self.info.pid, regs)?;
                }
                println!("<<子プロセスが停止しました : PC = {:#x}>>", regs.rip);

                Ok(State::Running(self))
            }
            _ => Err("waitpidの返り値が不正です".into()),
        }
    }

    fn step_and_break(mut self) -> Result<State, DynError> {
        let regs = ptrace::getregs(self.info.pid)?;
        // ripがプログラムカウンタを表す。このアドレスがブレークポイントと同じだったらステップを実行
        if Some((regs.rip) as *mut c_void) == self.info.brk_addr {
            // ここも第2引数は実行時に送信するシグナル
            ptrace::step(self.info.pid, None)?;
            match waitpid(self.info.pid, None)? {
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                    println!("<<子プロセスが終了しました>>");
                    return Ok(State::NotRunning(ZDbg::<NotRunning> {
                        info: self.info,
                        _state: NotRunning,
                    }));
                }
                _ => (),
            }
            self.set_break()?; // 再度ブレークポイント設定
        }

        Ok(State::Running(self))
    }

    fn do_continue(self) -> Result<State, DynError> {
        // ブレークポイントで止まっていた場合は、1ステップ実行後に再設定
        match self.step_and_break()? {
            State::Running(r) => {
                // 第2引数は再開時に送信するシグナル。Noneのときはシグナルは送信されない
                ptrace::cont(r.info.pid, None)?;
                // ここでは子プロセスが終了する可能性がある
                r.wait_child()
            }
            // 遷移後の状態を返している
            n => Ok(n),
        }
    }

    fn do_break(&mut self, cmd: &[&str]) -> Result<(), DynError> {
        if self.set_break_addr(cmd) {
            self.set_break()?;
        }
        Ok(())
    }

    fn do_exit(self) -> Result<(), DynError> {
        loop {
            // pidのプロセスはkillする。ptraceでもプロセスをkillできるんだな〜
            ptrace::kill(self.info.pid)?;
            match waitpid(self.info.pid, None)? {
                // 終了待ち
                WaitStatus::Exited(..) | WaitStatus::Signaled(..) => return Ok(()),
                _ => (),
            }
        }
    }

    fn do_stepi(self) -> Result<State, DynError> {
        let regs = ptrace::getregs(self.info.pid)?;
        if Some((regs.rip) as *mut c_void) == self.info.brk_addr {
            unsafe {
                // ここの分岐は次の実行がbpの時、メモリの内容をもとに戻してから実行する必要がある
                ptrace::write(
                    self.info.pid,
                    self.info.brk_addr.unwrap(),
                    self.info.brk_val as *mut c_void,
                )?;
                self.step_and_break()
            }
        } else {
            ptrace::setregs(self.info.pid, regs)?;
            self.wait_child()
        }
    }

    pub fn do_cmd(mut self, cmd: &[&str]) -> Result<State, DynError> {
        if cmd.is_empty() {
            return Ok(State::Running(self));
        }

        match cmd[0] {
            "break" | "b" => self.do_break(cmd)?,
            "continue" | "c" => return self.do_continue(),
            "registers" | "regs" => {
                // レジスタ情報の取得
                let regs = ptrace::getregs(self.info.pid)?;
                // 取得したレジスタ情報の表示
                print_regs(&regs);
            }
            "stepi" | "s" => return self.do_stepi(),
            "run" | "r" => eprintln!("<<すでに実行中です>>"),
            "exit" => {
                self.do_exit()?;
                return Ok(State::Exit);
            }
            _ => self.do_cmd_common(cmd),
        }

        Ok(State::Running(self))
    }
}

fn print_regs(regs: &user_regs_struct) {
    println!(
        r#"RIP: {:#016x}, RSP: {:#016x}, RBP: {:#016x}
RAX: {:#016x}, RBX: {:#016x}, RCX: {:#016x}
RDX: {:#016x}, RSI: {:#016x}, RDI: {:#016x}
 R8: {:#016x},  R9: {:#016x}, R10: {:#016x}
R11: {:#016x}, R12: {:#016x}, R13: {:#016x}
R14: {:#016x}, R15: {:#016x}
            "#,
        regs.rip,
        regs.rsp,
        regs.rbp,
        regs.rax,
        regs.rbx,
        regs.rcx,
        regs.rdx,
        regs.rsi,
        regs.rdi,
        regs.r8,
        regs.r9,
        regs.r10,
        regs.r11,
        regs.r12,
        regs.r13,
        regs.r14,
        regs.r15
    );
}

fn get_break_addr(cmd: &[&str]) -> Option<*mut c_void> {
    if cmd.len() < 2 {
        eprintln!("<<アドレスを指定してください\n 例：break 0x8000>>");
        return None;
    }

    let addr_str = cmd[1];
    if &addr_str[0..2] != "0x" {
        eprintln!("<<アドレスは16進数のみで指定可能です\n 例：break 0x8000>>");
        return None;
    }

    let addr = match usize::from_str_radix(&addr_str[2..], 16) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("<<アドレス変換エラー : {e}>>");
            return None;
        }
    } as *mut c_void;

    Some(addr)
}
