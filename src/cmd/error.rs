use std::error::Error;
use std::fmt::Display;

#[derive(Debug, PartialEq)]
pub enum CommandErrorCode {
    UninterpretableInputFormat,
    InvalidHexadecimalInputString,
    CannotOpenFile,
    ErrorInFileReading,
}

impl Clone for CommandErrorCode {
    fn clone(&self) -> Self { return *self; }
}

impl Copy for CommandErrorCode {}

#[derive(Debug)]
pub struct CommandError {
    err_code: CommandErrorCode
}

impl CommandError {

    pub fn new(err_code: CommandErrorCode) -> Self {
        return Self{ err_code: err_code };
    }

}

impl Display for CommandError {

    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return write!(f, "[!Err]: {}.", match &self.err_code {
            CommandErrorCode::UninterpretableInputFormat    => "uninterpretable data-fomat",
            CommandErrorCode::InvalidHexadecimalInputString => "invalid hexadecimal string",
            CommandErrorCode::CannotOpenFile                => "cannot open the file",
            CommandErrorCode::ErrorInFileReading            => "an error occurred while reading the file",
        });
    }

}

impl Error for CommandError {}