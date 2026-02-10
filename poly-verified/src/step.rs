/// Trait for deterministic step functions.
///
/// Given the previous state and inputs, produce the next state.
/// Must be deterministic: same inputs → same output.
pub trait StepFunction {
    fn execute(&self, state: &[u8], inputs: &[u8]) -> Vec<u8>;
}

/// Blanket implementation so closures work as StepFunction.
impl<F> StepFunction for F
where
    F: Fn(&[u8], &[u8]) -> Vec<u8>,
{
    fn execute(&self, state: &[u8], inputs: &[u8]) -> Vec<u8> {
        (self)(state, inputs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_step_function_closure() {
        let step = |state: &[u8], inputs: &[u8]| -> Vec<u8> {
            state.iter().zip(inputs.iter()).map(|(a, b)| a ^ b).collect()
        };

        let result = step.execute(&[0x01, 0x02], &[0xFF, 0x00]);
        assert_eq!(result, vec![0xFE, 0x02]);
    }
}
