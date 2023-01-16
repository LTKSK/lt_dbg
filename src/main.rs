/*  1. ackerman関数によるデバッガの演習用
// use num::{BigUint, FromPrimitive, One, Zero};

// const M: usize = 4;
// const N: usize = 4;

// fn main() {
//     let m = M;
//     let n = BigUint::from_usize(N).unwrap();
//     let a = ackerman(m, n.clone());
//     println!("ackerman({M}, {N}) = {a}");
// }

// fn ackerman(m: usize, n: BigUint) -> BigUint {
//     let one: BigUint = One::one();
//     let zero: BigUint = Zero::zero();

//     if m == 0 {
//         n + one
//     } else if n == zero {
//         ackerman(m - 1, one)
//     } else {
//         ackerman(m - 1, ackerman(m, n - one))
//     }
// }
*/

/*  2. プロセス停止をsignalとint命令で行う
use std::arch::asm;
use nix::{
    sys::signal::{kill, Signal},
    unistd::getpid,
};
fn main() {
    println!("int 3");
    unsafe { asm!("int 3") };

    println!("kill -SIGTRAP");
    let pid = getpid();
    // SIGTRAPを自身に送出
    kill(pid, Signal::SIGTRAP).unwrap();

    for i in 0..3 {
        // 後で使う目印のnop命令。何もしない命令
        unsafe { asm!("nop") };
        println!("i = {i}");
    }
}
*/

mod dbg;
mod helper;

use dbg::{State, ZDbg};
use helper::DynError;
use rustyline::{error::ReadlineError, Editor};
use std::env;

fn main() -> Result<(), DynError> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        let msg = format!("引数が必要です\n 例: {} 実行ファイル [引数*]", args[0]).into();
        return Err(msg.into());
    }

    run_dbg(&args[1])?;
    Ok(())
}

fn run_dbg(filename: &str) -> Result<(), DynError> {
    let debugger = ZDbg::new(filename.to_string());
    let mut state = State::NotRunning(debugger);
    let mut r1 = Editor::<()>::new()?;

    loop {
        match r1.readline("zdbg > ") {
            Ok(line) => {
                let trimed = line.trim();
                let cmd: Vec<&str> = trimed.split(' ').filter(|c| !c.is_empty()).collect();
                state = match state {
                    State::Running(r) => r.do_cmd(&cmd)?,
                    State::NotRunning(n) => n.do_cmd(&cmd)?,
                    _ => break,
                };
                if let State::Exit = state {
                    break;
                }
                r1.add_history_entry(line);
            }
            Err(ReadlineError::Interrupted) => eprintln!("<<終了は　C-d>>"),
            _ => {
                if let State::Running(r) = state {
                    r.do_cmd(&["exit"])?;
                };
                break;
            }
        }
    }
    Ok(())
}
