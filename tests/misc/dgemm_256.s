	.text
	.file	"dgemm_256.c"
	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3
.LCPI0_0:
	.xword	4472406533629990549     // double 1.0000000000000001E-9
	.text
	.globl	get_dtime
	.p2align	2
	.type	get_dtime,@function
get_dtime:                              // @get_dtime
// BB#0:
	sub	sp, sp, #32             // =32
	orr	w0, wzr, #0x1
	mov	x1, sp
	stp	x29, x30, [sp, #16]     // 8-byte Folded Spill
	add	x29, sp, #16            // =16
	bl	clock_gettime
	ldp	d0, d1, [sp]
	adrp	x8, .LCPI0_0
	ldr	d2, [x8, :lo12:.LCPI0_0]
	ldp	x29, x30, [sp, #16]     // 8-byte Folded Reload
	scvtf	d0, d0
	scvtf	d1, d1
	fmadd	d0, d1, d2, d0
	add	sp, sp, #32             // =32
	ret
.Lfunc_end0:
	.size	get_dtime, .Lfunc_end0-get_dtime

	.section	.rodata.cst8,"aM",@progbits,8
	.p2align	3
.LCPI1_0:
	.xword	4472406533629990549     // double 1.0000000000000001E-9
.LCPI1_1:
	.xword	4382569440205035030     // double 1.0000000000000001E-15
.LCPI1_2:
	.xword	4652007308841189376     // double 1000
	.text
	.globl	main
	.p2align	2
	.type	main,@function
main:                                   // @main
// BB#0:
	addvl	sp, sp, #-2
	str	d8, [sp, #-32]!         // 8-byte Folded Spill
	str	x28, [sp, #8]           // 8-byte Folded Spill
	stp	x20, x19, [sp, #16]     // 8-byte Folded Spill
	stp	x29, x30, [sp, #32]     // 8-byte Folded Spill
	add	x29, sp, #32            // =32
	sub	sp, sp, #16             // =16
	rdvl	x8, #1
	cmp	x8, #17                 // =17
	b.hs	.LBB1_2
// BB#1:
	adrp	x0, c
	mov	w1, wzr
	add	x0, x0, :lo12:c
	orr	w2, wzr, #0x80000
	bl	memset
	b	.LBB1_4
.LBB1_2:
	orr	w9, wzr, #0x80000
	adrp	x10, c
	mov	x8, xzr
	add	x10, x10, :lo12:c
	whilelo	p0.b, xzr, x9
	mov	z0.b, #0                // =0x0
.LBB1_3:                                // =>This Inner Loop Header: Depth=1
	st1b	{z0.b}, p0, [x10, x8]
	addvl	x8, x8, #1
	whilelo	p0.b, x8, x9
	b.mi	.LBB1_3
.LBB1_4:
	cntd	x10
	adrp	x20, a
	mov	z3.d, x10
	adrp	x10, b
	mov	x8, xzr
	orr	w9, wzr, #0x100
	index	z0.d, #0, #1
	ptrue	p2.d
	add	x20, x20, :lo12:a
	mov	z1.d, #0                // =0x0
	fmov	z2.d, #1.00000000
	add	x10, x10, :lo12:b
.LBB1_5:                                // =>This Loop Header: Depth=1
                                        //     Child Loop BB1_6 Depth 2
	and	x12, x8, #0xffffffff
	lsl	x13, x8, #8
	whilelo	p3.d, xzr, x9
	mov	x11, xzr
	mov	z4.d, x13
	mov	z5.d, x12
	mov	p0.b, p3.b
	mov	z6.d, z0.d
.LBB1_6:                                //   Parent Loop BB1_5 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	add	z16.d, z6.d, z4.d
	lsl	x12, x8, #11
	cmpeq	p1.d, p2/z, z5.d, z6.d
	add	z7.d, z6.d, z3.d
	scvtf	z16.d, p2/m, z16.s
	add	x13, x20, x12
	fmov	x14, d6
	incd	x11
	add	x12, x10, x12
	sel	z6.d, p1, z2.d, z1.d
	st1d	{z16.d}, p0, [x13, x14, lsl #3]
	st1d	{z6.d}, p0, [x12, x14, lsl #3]
	whilelo	p0.d, x11, x9
	mov	z6.d, z7.d
	b.mi	.LBB1_6
// BB#7:                                //   in Loop: Header=BB1_5 Depth=1
	add	x8, x8, #1              // =1
	cmp	x8, #256                // =256
	b.ne	.LBB1_5
// BB#8:
	orr	w0, wzr, #0x1
	mov	x1, sp
	str	p3, [x29, #8, mul vl]   // 2-byte Folded Spill
	bl	clock_gettime
	ldp	d0, d1, [sp]
	adrp	x10, .LCPI1_0
	ldr	d8, [x10, :lo12:.LCPI1_0]
	ldr	p2, [x29, #8, mul vl]   // 2-byte Folded Reload
	adrp	x9, c
	adrp	x10, b
	scvtf	d0, d0
	scvtf	d1, d1
	ptrue	p1.d
	mov	x8, xzr
	adrp	x19, main.time
	add	x9, x9, :lo12:c
	add	x10, x10, :lo12:b
	fmadd	d0, d1, d8, d0
	orr	w11, wzr, #0x100
	str	d0, [x19, :lo12:main.time]
.LBB1_9:                                // =>This Loop Header: Depth=1
                                        //     Child Loop BB1_10 Depth 2
                                        //       Child Loop BB1_11 Depth 3
	mov	x12, xzr
	mov	x13, x10
.LBB1_10:                               //   Parent Loop BB1_9 Depth=1
                                        // =>  This Loop Header: Depth=2
                                        //       Child Loop BB1_11 Depth 3
	add	x14, x20, x8, lsl #11
	add	x14, x14, x12, lsl #3
	ld1rd	{z0.d}, p1/z, [x14]
	mov	x14, xzr
	mov	p0.b, p2.b
.LBB1_11:                               //   Parent Loop BB1_9 Depth=1
                                        //     Parent Loop BB1_10 Depth=2
                                        // =>    This Inner Loop Header: Depth=3
	ld1d	{z1.d}, p0/z, [x13, x14, lsl #3]
	ld1d	{z2.d}, p0/z, [x9, x14, lsl #3]
	fmad	z1.d, p1/m, z0.d, z2.d
	st1d	{z1.d}, p0, [x9, x14, lsl #3]
	incd	x14
	whilelo	p0.d, x14, x11
	b.mi	.LBB1_11
// BB#12:                               //   in Loop: Header=BB1_10 Depth=2
	add	x12, x12, #1            // =1
	add	x13, x13, #2048         // =2048
	cmp	x12, #256               // =256
	b.ne	.LBB1_10
// BB#13:                               //   in Loop: Header=BB1_9 Depth=1
	add	x8, x8, #1              // =1
	add	x9, x9, #2048           // =2048
	cmp	x8, #256                // =256
	b.ne	.LBB1_9
// BB#14:
	orr	w0, wzr, #0x1
	mov	x1, sp
	bl	clock_gettime
	ldp	d0, d1, [sp]
	ldr	d3, [x19, :lo12:main.time]
	adrp	x10, .LCPI1_1
	ldr	d2, [x10, :lo12:.LCPI1_1]
	scvtf	d0, d0
	scvtf	d1, d1
	adrp	x9, c
	fmadd	d0, d1, d8, d0
	adrp	x10, a
	mov	x8, xzr
	add	x9, x9, :lo12:c
	fsub	d0, d0, d3
	add	x10, x10, :lo12:a
	str	d0, [x19, :lo12:main.time]
.LBB1_15:                               // =>This Loop Header: Depth=1
                                        //     Child Loop BB1_16 Depth 2
	mov	x11, xzr
	mov	x12, x10
	mov	x13, x9
.LBB1_16:                               //   Parent Loop BB1_15 Depth=1
                                        // =>  This Inner Loop Header: Depth=2
	ldr	d1, [x13]
	ldr	d0, [x12]
	fsub	d3, d1, d0
	fabs	d3, d3
	fcmp	d3, d2
	b.gt	.LBB1_20
// BB#17:                               //   in Loop: Header=BB1_16 Depth=2
	add	x11, x11, #1            // =1
	add	x13, x13, #8            // =8
	add	x12, x12, #8            // =8
	cmp	x11, #255               // =255
	b.le	.LBB1_16
// BB#18:                               //   in Loop: Header=BB1_15 Depth=1
	add	x8, x8, #1              // =1
	add	x9, x9, #2048           // =2048
	add	x10, x10, #2048         // =2048
	cmp	x8, #256                // =256
	b.lt	.LBB1_15
// BB#19:
	adrp	x0, .Lstr
	add	x0, x0, :lo12:.Lstr
	bl	puts
	adrp	x8, .LCPI1_2
	ldr	d0, [x19, :lo12:main.time]
	ldr	d1, [x8, :lo12:.LCPI1_2]
	adrp	x0, .L.str.3
	add	x0, x0, :lo12:.L.str.3
	fmul	d0, d0, d1
	bl	printf
	mov	w0, wzr
	add	sp, sp, #16             // =16
	ldp	x29, x30, [sp, #32]     // 8-byte Folded Reload
	ldp	x20, x19, [sp, #16]     // 8-byte Folded Reload
	ldr	x28, [sp, #8]           // 8-byte Folded Reload
	ldr	d8, [sp], #32           // 8-byte Folded Reload
	addvl	sp, sp, #2
	ret
.LBB1_20:
	adrp	x0, .L.str
	add	x0, x0, :lo12:.L.str
	bl	printf
	adrp	x0, .Lstr.4
	add	x0, x0, :lo12:.Lstr.4
	bl	puts
	movn	w0, #0
	bl	exit
.Lfunc_end1:
	.size	main, .Lfunc_end1-main

	.type	main.time,@object       // @main.time
	.local	main.time
	.comm	main.time,8,8
	.type	a,@object               // @a
	.comm	a,524288,8
	.type	b,@object               // @b
	.comm	b,524288,8
	.type	c,@object               // @c
	.comm	c,524288,8
	.type	.L.str,@object          // @.str
	.section	.rodata.str1.1,"aMS",@progbits,1
.L.str:
	.asciz	"%lf, actual : %lf\n"
	.size	.L.str, 19

	.type	.L.str.3,@object        // @.str.3
.L.str.3:
	.asciz	"time = %lf [msec]\n"
	.size	.L.str.3, 19

	.type	.Lstr,@object           // @str
.Lstr:
	.asciz	"PASS"
	.size	.Lstr, 5

	.type	.Lstr.4,@object         // @str.4
.Lstr.4:
	.asciz	"FAILED"
	.size	.Lstr.4, 7


	.ident	"ARM clang version 1.0 (build number 19) (based on LLVM 3.9.0svn)"
	.section	".note.GNU-stack","",@progbits
