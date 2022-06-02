use crate::{
    evm_circuit::{
        execution::ExecutionGadget,
        step::ExecutionState,
        util::{
            common_gadget::SameContextGadget,
            constraint_builder::{ConstraintBuilder, StepStateTransition, Transition::Delta},
            math_gadget::{CmpWordsGadget, IsEqualGadget},
            select, CachedRegion, Cell, Word,
        },
        witness::{Block, Call, ExecStep, Transaction},
    },
    util::Expr,
};
use eth_types::{evm_types::OpcodeId, Field, ToLittleEndian};
use halo2_proofs::plonk::Error;

#[derive(Clone, Debug)]
pub(crate) struct ComparatorGadget<F> {
    same_context: SameContextGadget<F>,
    a: Word<F>,
    b: Word<F>,
    result: Cell<F>,
    cmp: CmpWordsGadget<F>,
    is_eq: IsEqualGadget<F>,
    is_gt: IsEqualGadget<F>,
}

impl<F: Field> ExecutionGadget<F> for ComparatorGadget<F> {
    const NAME: &'static str = "CMP";

    const EXECUTION_STATE: ExecutionState = ExecutionState::CMP;

    fn configure(cb: &mut ConstraintBuilder<F>) -> Self {
        let opcode = cb.query_cell();

        let a = cb.query_word();
        let b = cb.query_word();

        // Check if opcode is EQ
        let is_eq = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::EQ.expr());
        // Check if opcode is GT. For GT we swap the stack inputs so that we
        // actually do greater than instead of smaller than.
        let is_gt = IsEqualGadget::construct(cb, opcode.expr(), OpcodeId::GT.expr());

        let cmp = CmpWordsGadget::construct(cb, &a, &b);

        // The result is:
        // - `lt` when LT or GT
        // - `eq` when EQ
        // Use copy to avoid degree too high for stack_push below.
        let result = cb.copy(select::expr(is_eq.expr(), cmp.eq.clone(), cmp.lt.clone()));

        // Pop a and b from the stack, push the result on the stack.
        // When swap is eabled we swap stack places between a and b.
        // We can push result here directly because
        // it only uses the LSB of a word.
        cb.stack_pop(select::expr(is_gt.expr(), b.expr(), a.expr()));
        cb.stack_pop(select::expr(is_gt.expr(), a.expr(), b.expr()));
        cb.stack_push(result.expr());

        // State transition
        let step_state_transition = StepStateTransition {
            rw_counter: Delta(3.expr()),
            program_counter: Delta(1.expr()),
            stack_pointer: Delta(1.expr()),
            gas_left: Delta(-OpcodeId::LT.constant_gas_cost().expr()),
            ..Default::default()
        };
        let same_context = SameContextGadget::construct(cb, opcode, step_state_transition);

        Self {
            same_context,
            a,
            b,
            result,
            cmp,
            is_eq,
            is_gt,
        }
    }

    fn assign_exec_step(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        block: &Block<F>,
        _: &Transaction,
        _: &Call,
        step: &ExecStep,
    ) -> Result<(), Error> {
        self.same_context.assign_exec_step(region, offset, step)?;

        let opcode = step.opcode.unwrap();

        // EQ op check
        self.is_eq.assign(
            region,
            offset,
            F::from(opcode.as_u8() as u64),
            F::from(OpcodeId::EQ.as_u8() as u64),
        )?;

        // swap when doing GT
        let is_gt = self.is_gt.assign(
            region,
            offset,
            F::from(opcode.as_u8() as u64),
            F::from(OpcodeId::GT.as_u8() as u64),
        )?;

        let indices = if is_gt == F::one() {
            [step.rw_indices[1], step.rw_indices[0]]
        } else {
            [step.rw_indices[0], step.rw_indices[1]]
        };
        let [a, b] = indices.map(|idx| block.rws[idx].stack_value());
        let result = block.rws[step.rw_indices[2]].stack_value();

        self.cmp.assign(region, offset, a, b)?;

        self.a.assign(region, offset, Some(a.to_le_bytes()))?;
        self.b.assign(region, offset, Some(b.to_le_bytes()))?;
        self.result
            .assign(region, offset, Some(F::from(result.low_u64())))?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use crate::{evm_circuit::test::rand_word, test_util::run_test_circuits};
    use eth_types::evm_types::OpcodeId;
    use eth_types::{bytecode, Word};
    use mock::TestContext;

    fn test_ok(opcode: OpcodeId, a: Word, b: Word, _c: Word) {
        let bytecode = bytecode! {
            PUSH32(b)
            PUSH32(a)
            .write_op(opcode)
            STOP
        };

        assert_eq!(
            run_test_circuits(
                TestContext::<2, 1>::simple_ctx_with_bytecode(bytecode).unwrap(),
                None
            ),
            Ok(())
        );
    }

    #[test]
    fn comparator_gadget_simple() {
        let hi_lo = Word::from_big_endian(&[[255u8; 16], [0u8; 16]].concat());
        let lo_hi = Word::from_big_endian(&[[0u8; 16], [255u8; 16]].concat());

        // LT
        // hi_lo < lo_hi == 0
        test_ok(OpcodeId::LT, hi_lo, lo_hi, 0.into());
        // lo_hi < hi_lo == 1
        test_ok(OpcodeId::LT, lo_hi, hi_lo, 1.into());
        // hi_lo < hi_lo == 0
        test_ok(OpcodeId::LT, hi_lo, hi_lo, 0.into());
        // lo_hi < lo_hi == 0
        test_ok(OpcodeId::LT, lo_hi, lo_hi, 0.into());

        // GT
        // hi_lo > lo_hi == 1
        test_ok(OpcodeId::GT, hi_lo, lo_hi, 1.into());
        // lo_hi > hi_lo == 0
        test_ok(OpcodeId::GT, lo_hi, hi_lo, 0.into());
        // hi_lo > hi_lo == 0
        test_ok(OpcodeId::GT, hi_lo, hi_lo, 0.into());
        // lo_hi > lo_hi == 0
        test_ok(OpcodeId::GT, lo_hi, lo_hi, 0.into());

        // EQ
        // (hi_lo == lo_hi) == 0
        test_ok(OpcodeId::EQ, hi_lo, lo_hi, 0.into());
        // (lo_hi == hi_lo) == 0
        test_ok(OpcodeId::EQ, lo_hi, hi_lo, 0.into());
        // (hi_lo == hi_lo) == 1
        test_ok(OpcodeId::EQ, hi_lo, hi_lo, 1.into());
        // (lo_hi == lo_hi) == 1
        test_ok(OpcodeId::EQ, lo_hi, lo_hi, 1.into());
    }

    #[test]
    fn comparator_gadget_rand() {
        let a = rand_word();
        let b = rand_word();
        test_ok(OpcodeId::LT, a, b, Word::from((a < b) as usize));
        test_ok(OpcodeId::GT, a, b, Word::from((a > b) as usize));
        test_ok(OpcodeId::EQ, a, b, Word::from((a == b) as usize));
    }
}
