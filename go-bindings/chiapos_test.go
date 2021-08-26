package go_bindings

import "testing"

func TestPos(t *testing.T) {
	memo := []byte{1, 2, 3, 4, 5,6}
	plot_id_1 := []byte{35, 2, 52, 4, 51, 55, 23, 84, 91, 10, 111, 12, 13, 222, 151, 16,
		228, 211, 254, 45, 92, 198, 204, 10, 9, 10, 11, 129, 139, 171, 15, 23}
	t.Log(CreatePlotDisk(".", ".", ".", "cpp-test-plot.dat", 18, memo, plot_id_1,
		11, 0, 4000, 2, false))
}
