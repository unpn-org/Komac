use std::{
    borrow::Cow,
    collections::{BTreeMap, BTreeSet},
};

use tracing::warn;
use uuid::Uuid;

use super::{
    Kernel32,
    memory::Memory,
    syntax::{Declaration, Io, Kind, Parameter},
};
use crate::analysis::installers::nsis::{
    Variables,
    entry::ExecFlags,
    file_system::FileSystem,
    registry::{RegRoot, Registry},
    state::parse_int64,
    strings::PredefinedVar,
};

pub struct Context<'a, 'data> {
    pub variables: &'a mut Variables<'data>,
    pub stack: &'a mut Vec<Cow<'data, str>>,
    pub flags: &'a mut ExecFlags,
    pub registry: &'a mut Registry,
    pub files: &'a mut FileSystem,
}

#[derive(Clone, Debug)]
pub enum ShellInterface {
    Unknown,
    Link { wide: bool },
    Persist,
}

#[derive(Clone, Debug)]
pub enum Handle {
    Mutex(String),
    Snapshot,
    Process,
    Registry(RegRoot, String),
    ShellLink {
        object: u64,
        interface: ShellInterface,
        references: u32,
    },
    Module(String),
}

#[derive(Clone, Debug)]
pub struct Environment {
    pub pointer: usize,
    pub unicode: bool,
    pub native_machine: u16,
    pub process_machine: u16,
    pub version: (u32, u32, u32),
    pub version_revision: u32,
    pub version_manifest: bool,
    pub version_81_manifest: bool,
    pub ticks: u64,
}

impl Default for Environment {
    fn default() -> Self {
        let version = std::env::var("KOMAC_NSIS_WINDOWS_VERSION")
            .ok()
            .and_then(|v| {
                let parts: Vec<_> = v
                    .split('.')
                    .map(str::parse::<u32>)
                    .collect::<Result<_, _>>()
                    .ok()?;
                matches!(parts.len(), 3 | 4).then(|| {
                    (
                        (parts[0], parts[1], parts[2]),
                        parts.get(3).copied().unwrap_or_default(),
                    )
                })
            })
            // Windows 11 26H2, latest released build checked on 2026-11-06.
            // https://learn.microsoft.com/windows/release-health/windows11-release-information
            .unwrap_or(((10, 0, 26300), 9818));
        let native_machine = match std::env::var("KOMAC_NSIS_NATIVE_ARCH").as_deref() {
            Ok("x86") => 0x14c,
            Ok("arm64") => 0xaa64,
            _ => 0x8664,
        };
        Self {
            pointer: 4,
            unicode: true,
            native_machine,
            process_machine: 0x14c,
            version: version.0,
            version_revision: version.1,
            version_manifest: true,
            version_81_manifest: false,
            ticks: 1000,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Engine {
    pub memory: Memory,
    pub environment: Environment,
    pub last_error: u32,
    pub handles: BTreeMap<u64, Handle>,
    pub procedures: BTreeMap<u64, Declaration>,
    pub links: BTreeMap<u64, String>,
    pub assumptions: BTreeSet<&'static str>,
    next_handle: u64,
}

pub fn integer(value: &str) -> u64 {
    value
        .split('|')
        .fold(0, |n, part| n | parse_int64(part.trim()) as u64)
}

struct Argument {
    spec: Parameter,
    value: u64,
    cell: Option<u64>,
}

impl Engine {
    pub fn assume(&mut self, domain: &'static str) {
        if self.assumptions.insert(domain) {
            let e = &self.environment;
            warn!(
                domain,
                windows = ?e.version,
                revision = e.version_revision,
                native_machine = format_args!("{:#x}", e.native_machine),
                "System API uses a simulated Windows environment; environment-dependent metadata requires independent validation"
            );
        }
    }

    pub fn handle(&mut self, handle: Handle) -> Option<u64> {
        if self.handles.len() + self.procedures.len() >= 4096 {
            return None;
        }
        self.next_handle = self.next_handle.checked_add(1)?;
        let address = 0x6000_0000u64.checked_add(self.next_handle.checked_mul(16)?)?;
        if address > 0x7fff_ffff {
            return None;
        }
        self.handles.insert(address, handle);
        Some(address)
    }

    pub fn input(io: &Io, context: &mut Context<'_, '_>) -> String {
        match io {
            Io::None | Io::Null => String::new(),
            Io::Literal(value) => value.clone(),
            Io::Stack => context.stack.pop().map(Cow::into_owned).unwrap_or_default(),
            Io::Register(index) => context
                .variables
                .get(index)
                .map(str::to_owned)
                .unwrap_or_else(|| {
                    index
                        .checked_sub(Variables::NUM_REGISTERS)
                        .and_then(|i| PredefinedVar::try_from(i).ok())
                        .map(|v| v.as_str().to_owned())
                        .unwrap_or_default()
                }),
        }
    }

    pub fn output(io: &Io, value: String, context: &mut Context<'_, '_>) {
        match io {
            Io::Register(index) => {
                context.variables.insert(*index, value);
            }
            Io::Stack => context.stack.push(Cow::Owned(value)),
            _ => {}
        }
    }

    pub fn wide(&self, kind: Kind) -> bool {
        kind == Kind::Wide || (kind == Kind::Text && self.environment.unicode)
    }

    fn scalar_size(&self, kind: Kind) -> usize {
        match kind {
            Kind::Long => 8,
            Kind::Int | Kind::Void => 4,
            _ => self.environment.pointer,
        }
    }

    fn field_size(&self, parameter: &Parameter) -> Option<usize> {
        if parameter.reference {
            return Some(self.environment.pointer);
        }
        if let Some(count) = parameter.array {
            return count.checked_mul(if self.wide(parameter.kind) { 2 } else { 1 });
        }
        Some(if parameter.kind == Kind::Guid {
            16
        } else {
            self.scalar_size(parameter.kind)
        })
    }

    fn encode(&mut self, spec: &Parameter, input: &str, temporaries: &mut Vec<u64>) -> Option<u64> {
        match spec.kind {
            Kind::Void => Some(0),
            Kind::Ansi | Kind::Wide | Kind::Text => {
                let address = self
                    .memory
                    .alloc_string(input, self.wide(spec.kind), 8192)?;
                temporaries.push(address);
                Some(address)
            }
            Kind::Guid => {
                let address = self.memory.alloc(16)?;
                temporaries.push(address);
                if !input.is_empty() {
                    self.memory.write(
                        address,
                        &Uuid::parse_str(input.trim_matches(['{', '}']))
                            .ok()?
                            .to_bytes_le(),
                    )?;
                }
                Some(address)
            }
            Kind::RegisterMemory => None,
            _ => Some(integer(input)),
        }
    }

    fn format(&self, spec: &Parameter, value: u64) -> Option<String> {
        match spec.kind {
            Kind::Void => Some(String::new()),
            Kind::Ansi | Kind::Wide | Kind::Text => self.memory.string(value, self.wide(spec.kind)),
            Kind::Guid => Some(format!(
                "{{{}}}",
                Uuid::from_bytes_le(self.memory.read(value, 16)?.try_into().ok()?)
                    .hyphenated()
                    .to_string()
                    .to_uppercase()
            )),
            Kind::Long => Some((value as i64).to_string()),
            Kind::Pointer | Kind::Callback | Kind::RegisterMemory
                if self.environment.pointer == 8 =>
            {
                Some((value as i64).to_string())
            }
            Kind::Int if spec.array.is_some_and(|n| n > 0 && n < 4) => Some(value.to_string()),
            _ => Some((value as u32 as i32).to_string()),
        }
    }

    fn marshal(
        &mut self,
        spec: &Parameter,
        context: &mut Context<'_, '_>,
        temporaries: &mut Vec<u64>,
    ) -> Option<Argument> {
        let input = Self::input(&spec.input, context);
        let value = if spec.input == Io::Null {
            0
        } else {
            self.encode(spec, &input, temporaries)?
        };
        let cell = if spec.reference {
            let address = self.memory.alloc(self.scalar_size(spec.kind))?;
            temporaries.push(address);
            self.memory
                .put_number(address, value, self.scalar_size(spec.kind))?;
            Some(address)
        } else {
            None
        };
        Some(Argument {
            spec: spec.clone(),
            value,
            cell,
        })
    }

    fn finish(&self, argument: &Argument, context: &mut Context<'_, '_>) {
        if matches!(argument.spec.output, Io::None | Io::Null) {
            return;
        }
        let value = argument.cell.map_or(Some(argument.value), |cell| {
            self.memory
                .number(cell, self.scalar_size(argument.spec.kind))
        });
        let output = value
            .and_then(|v| self.format(&argument.spec, v))
            .unwrap_or_else(|| "$ERROR".to_owned());
        Self::output(&argument.spec.output, output, context);
    }

    fn unknown(
        &mut self,
        declaration: &Declaration,
        arguments: &[Argument],
        context: &mut Context<'_, '_>,
    ) {
        for argument in arguments.iter().rev() {
            self.memory
                .invalidate(argument.cell.unwrap_or(argument.value));
        }
        for parameter in declaration.parameters.iter().rev() {
            if parameter.output != Io::None {
                Self::output(&parameter.output, "$ERROR".to_owned(), context);
            }
        }
        if declaration.result.output != Io::None {
            Self::output(&declaration.result.output, "$ERROR".to_owned(), context);
        }
        if declaration.options.status {
            context.stack.push(Cow::Borrowed("$ERROR"));
        }
        if declaration.options.last_error {
            context.stack.push(Cow::Borrowed("$ERROR"));
        }
    }

    fn function_call(
        &mut self,
        declaration: &Declaration,
        context: &mut Context<'_, '_>,
        kernel: &mut Kernel32,
    ) -> bool {
        let mut temporaries = Vec::new();
        let arguments = declaration
            .parameters
            .iter()
            .map(|p| self.marshal(p, context, &mut temporaries))
            .collect::<Vec<_>>();
        let complete = arguments.iter().all(Option::is_some);
        let arguments: Vec<_> = arguments.into_iter().flatten().collect();
        Self::input(&declaration.result.input, context);
        let success = if complete {
            let values: Vec<_> = arguments
                .iter()
                .map(|a| a.cell.unwrap_or(a.value))
                .collect();
            if let Some(value) = self.dispatch(
                &declaration.target,
                &values,
                &declaration.parameters,
                context,
                kernel,
            ) {
                for argument in arguments.iter().rev() {
                    self.finish(argument, context);
                }
                Self::output(
                    &declaration.result.output,
                    self.format(&declaration.result, value)
                        .unwrap_or_else(|| "$ERROR".to_owned()),
                    context,
                );
                if declaration.options.status {
                    context.stack.push(Cow::Borrowed("ok"));
                }
                if declaration.options.last_error {
                    context.stack.push(Cow::Owned(self.last_error.to_string()));
                }
                true
            } else {
                self.unknown(declaration, &arguments, context);
                false
            }
        } else {
            self.unknown(declaration, &arguments, context);
            false
        };
        for address in temporaries {
            self.memory.free(address);
        }
        success
    }

    fn structure(
        &mut self,
        declaration: &Declaration,
        context: &mut Context<'_, '_>,
    ) -> Option<u64> {
        let mut size = 0usize;
        let mut offsets = Vec::new();
        for parameter in &declaration.parameters {
            if declaration.options.syntax2 && parameter.aligned {
                let alignment = match parameter.kind {
                    Kind::Ansi | Kind::Wide | Kind::Text => {
                        if self.wide(parameter.kind) {
                            2
                        } else {
                            1
                        }
                    }
                    Kind::Guid => 16,
                    Kind::Void => 0,
                    _ => self.field_size(parameter)?,
                };
                if alignment != 0 {
                    if !alignment.is_power_of_two() {
                        return None;
                    }
                    size = size.checked_add(alignment - 1)? & !(alignment - 1);
                }
            }
            offsets.push(size);
            size = size.checked_add(self.field_size(parameter)?)?;
        }
        if size > 8 * 1024 * 1024 {
            return None;
        }
        let pointer_text = declaration.target.strip_prefix('*')?;
        if size == 0 && !pointer_text.is_empty() {
            size = self.memory.size(integer(pointer_text))?;
        }
        let pointer = if pointer_text.is_empty() {
            self.memory.alloc(size.max(1))?
        } else {
            integer(pointer_text)
        };
        self.memory.available(pointer)?;
        let mut parameters = Vec::new();
        for (parameter, offset) in declaration.parameters.iter().zip(&offsets) {
            if parameter.reference {
                return None;
            }
            let address = pointer.checked_add(*offset as u64)?;
            let mut value = 0;
            if parameter.array.is_some() && parameter.kind == Kind::Long {
                value = size as u64;
                let width = self.field_size(parameter)?;
                if width > 8 {
                    return None;
                }
                self.memory.put_number(address, value, width)?;
            } else if parameter.input != Io::None && parameter.kind != Kind::Void {
                let input = Self::input(&parameter.input, context);
                let width = self.field_size(parameter)?;
                if parameter.array.is_some()
                    && matches!(parameter.kind, Kind::Ansi | Kind::Wide | Kind::Text)
                {
                    let mut bytes = Memory::encoded(&input, self.wide(parameter.kind));
                    bytes.resize(width, 0);
                    bytes.truncate(width);
                    self.memory.write(address, &bytes)?;
                } else if parameter.kind == Kind::Guid {
                    let bytes = Uuid::parse_str(input.trim_matches(['{', '}']))
                        .ok()?
                        .to_bytes_le();
                    if width != 16 {
                        return None;
                    }
                    self.memory.write(address, &bytes)?;
                } else if width > 8 {
                    return None;
                } else {
                    let mut retained = Vec::new();
                    value = self.encode(parameter, &input, &mut retained)?;
                    self.memory.put_number(address, value, width)?;
                }
            }
            parameters.push((parameter, address, value));
        }
        for (parameter, address, value) in parameters.into_iter().rev() {
            if parameter.output == Io::None {
                continue;
            }
            let output = if parameter.array == Some(0) && parameter.kind == Kind::Long {
                Some(value.to_string())
            } else if parameter.kind == Kind::Guid {
                self.format(parameter, address)
            } else if parameter.array.is_some()
                && matches!(parameter.kind, Kind::Ansi | Kind::Wide | Kind::Text)
            {
                self.memory
                    .inline_string(address, self.wide(parameter.kind), parameter.array?)
            } else {
                self.memory
                    .number(address, self.field_size(parameter)?)
                    .and_then(|v| self.format(parameter, v))
            };
            Self::output(
                &parameter.output,
                output.unwrap_or_else(|| "$ERROR".to_owned()),
                context,
            );
        }
        Self::output(
            &declaration.result.output,
            self.format(&declaration.result, pointer)?,
            context,
        );
        if declaration.options.status {
            context.stack.push(Cow::Borrowed("ok"));
        }
        if declaration.options.last_error {
            context.stack.push(Cow::Owned(self.last_error.to_string()));
        }
        Some(pointer)
    }

    pub fn call(
        &mut self,
        source: &str,
        context: &mut Context<'_, '_>,
        kernel: &mut Kernel32,
    ) -> bool {
        let Some(mut declaration) = Declaration::parse(source) else {
            return false;
        };
        let mut procedure = None;
        if !declaration.target.contains("::")
            && !declaration.target.starts_with('*')
            && !declaration.target.contains("->")
        {
            let address = integer(&declaration.target);
            let Some(saved) = self.procedures.get(&address).cloned() else {
                return false;
            };
            let retain = !saved.options.never_redefine;
            let mut inherited = saved.options;
            inherited.never_redefine = false;
            let options = declaration.options.inherit(inherited);
            if declaration.has_signature {
                declaration.target = saved.target.clone();
                for (parameter, previous) in
                    declaration.parameters.iter_mut().zip(&saved.parameters)
                {
                    *parameter = parameter.clone().inherit(previous);
                }
                declaration.result = if declaration.has_result {
                    declaration.result.inherit(&saved.result)
                } else {
                    saved.result.clone()
                };
            } else {
                declaration = saved;
            }
            declaration.options = options;
            if retain {
                self.procedures.insert(address, declaration.clone());
            }
            procedure = retain.then_some(address);
        }
        if declaration.target.starts_with('*') {
            if let Some(pointer) = self.structure(&declaration, context) {
                if declaration.target == "*"
                    && let Some(address) = procedure
                {
                    declaration.target = format!("*{pointer}");
                    self.procedures.insert(address, declaration);
                }
                true
            } else {
                self.unknown(&declaration, &[], context);
                false
            }
        } else {
            self.function_call(&declaration, context, kernel)
        }
    }

    pub fn get(&mut self, source: &str, context: &mut Context<'_, '_>) -> bool {
        let Some(declaration) = Declaration::parse(source) else {
            context.stack.push(Cow::Borrowed("$ERROR"));
            return false;
        };
        if !self.supports(&declaration.target) || self.procedures.len() >= 4096 {
            context.stack.push(Cow::Borrowed("$ERROR"));
            return false;
        }
        self.next_handle = self.next_handle.saturating_add(1);
        let address = 0x7000_0000 + self.next_handle * 16;
        let status = declaration.options.status;
        self.procedures.insert(address, declaration);
        context.stack.push(Cow::Owned(address.to_string()));
        if status {
            context.stack.push(Cow::Borrowed("ok"));
        }
        true
    }

    pub fn int64(stack: &mut Vec<Cow<'_, str>>) -> bool {
        if stack.len() < 2 {
            return false;
        }
        let n = stack.len();
        let a = integer(&stack[n - 1]) as i64;
        let op = &*stack[n - 2];
        let unary = matches!(op, "~" | "!");
        if !unary && n < 3 {
            return false;
        }
        let b = if unary {
            0
        } else {
            integer(&stack[n - 3]) as i64
        };
        let value = match op {
            "+" => a.wrapping_add(b),
            "-" => a.wrapping_sub(b),
            "*" => a.wrapping_mul(b),
            "/" => {
                if b == 0 {
                    0
                } else {
                    a.wrapping_div(b)
                }
            }
            "%" => {
                if b == 0 {
                    a
                } else {
                    a.wrapping_rem(b)
                }
            }
            "|" => a | b,
            "&" => a & b,
            "^" => a ^ b,
            "~" => !a,
            "!" => i64::from(a == 0),
            "||" => i64::from(a != 0 || b != 0),
            "&&" => i64::from(a != 0 && b != 0),
            "<<" => a.wrapping_shl(b as u32),
            ">>" => a.wrapping_shr(b as u32),
            ">>>" => (a as u64).wrapping_shr(b as u32) as i64,
            "<" => i64::from(a < b),
            ">" => i64::from(a > b),
            "=" | "==" => i64::from(a == b),
            _ => return false,
        };
        stack.truncate(n - if unary { 2 } else { 3 });
        stack.push(Cow::Owned(value.to_string()));
        true
    }
}
