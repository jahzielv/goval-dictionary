package redhat

import (
	"reflect"
	"sort"
	"testing"

	"github.com/k0kubun/pp"

	"github.com/vulsio/goval-dictionary/models"
)

func TestWalkRedHat(t *testing.T) {
	var tests = []struct {
		version  string
		cri      Criteria
		testIdx  map[string]RpminfoTest
		stateIdx map[string]RpminfoState
		expected []models.Package
	}{
		// {
		// 	version: "6",
		// 	cri: Criteria{
		// 		Criterions: []Criterion{
		// 			{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:    "kernel-headers",
		// 			Version: "0:2.6.32-71.7.1.el6",
		// 		},
		// 	},
		// },
		// {
		// 	version: "6",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterions: []Criterion{
		// 					{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
		// 					{Comment: "kernel-headers is signed with Red Hat redhatrelease2 key"},
		// 				},
		// 			},
		// 		},
		// 		Criterions: []Criterion{
		// 			{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
		// 			{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:    "kernel-headers",
		// 			Version: "0:2.6.32-71.7.1.el6",
		// 		},
		// 		{
		// 			Name:    "kernel-kdump",
		// 			Version: "0:2.6.32-71.7.1.el6",
		// 		},
		// 	},
		// },
		// {
		// 	version: "6",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterions: []Criterion{
		// 					{Comment: "bzip2 is earlier than 0:1.0.5-7.el6_0"},
		// 					{Comment: "bzip2 is signed with Red Hat redhatrelease2 key"},
		// 				},

		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "samba-domainjoin-gui is earlier than 0:3.5.4-68.el6_0.1"},
		// 							{Comment: "samba-domainjoin-gui is signed with Red Hat redhatrelease2 key"},
		// 						},
		// 					},
		// 				},
		// 			},
		// 			{
		// 				Criterions: []Criterion{
		// 					{Comment: "poppler-qt4 is signed with Red Hat redhatrelease2 key"},
		// 					{Comment: "poppler-qt4 is earlier than 0:0.12.4-3.el6_0.1"},
		// 				},
		// 			},
		// 		},
		// 		Criterions: []Criterion{
		// 			{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
		// 			{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:    "bzip2",
		// 			Version: "0:1.0.5-7.el6_0",
		// 		},
		// 		{
		// 			Name:    "samba-domainjoin-gui",
		// 			Version: "0:3.5.4-68.el6_0.1",
		// 		},
		// 		{
		// 			Name:    "poppler-qt4",
		// 			Version: "0:0.12.4-3.el6_0.1",
		// 		},
		// 		{
		// 			Name:    "kernel-kdump",
		// 			Version: "0:2.6.32-71.7.1.el6",
		// 		},
		// 	},
		// },
		// {
		// 	version: "6",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "rpm is earlier than 0:4.8.0-12.el6_0.2"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Red Hat Enterprise Linux 6 is installed"},
		// 				},
		// 			},
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "rpm is earlier than 0:4.8.0-19.el6_2.1"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Red Hat Enterprise Linux 6 is installed"},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:    "rpm",
		// 			Version: "0:4.8.0-19.el6_2.1",
		// 		},
		// 	},
		// },
		// {
		// 	version: "6",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "rpm is earlier than 0:4.8.0-12.el6_0.2"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Red Hat Enterprise Linux 6 is installed"},
		// 				},
		// 			},
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "rpm is earlier than 0:4.8.0-19.el7_0.1"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Red Hat Enterprise Linux 7 is installed"},
		// 				},
		// 			},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:    "rpm",
		// 			Version: "0:4.8.0-12.el6_0.2",
		// 		},
		// 	},
		// },
		// {
		// 	version: "8",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterions: []Criterion{
		// 					{Comment: "ruby is earlier than 0:2.5.5-105.module+el8.1.0+3656+f80bfa1d"},
		// 					{Comment: "ruby is signed with Red Hat redhatrelease2 key"},
		// 				},
		// 			},
		// 		},
		// 		Criterions: []Criterion{
		// 			{Comment: "Red Hat Enterprise Linux 8 is installed"},
		// 			{Comment: "Module ruby:2.5 is enabled"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:            "ruby",
		// 			Version:         "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
		// 			ModularityLabel: "ruby:2.5",
		// 		},
		// 	},
		// },
		// {
		// 	version: "8",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "libvirt is earlier than 0:4.5.0-42.module+el8.2.0+6024+15a2423f"},
		// 							{Comment: "libvirt is signed with Red Hat redhatrelease2 key"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Module virt:rhel is enabled"},
		// 				},
		// 			},
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterions: []Criterion{
		// 							{Comment: "libvirt is earlier than 0:4.5.0-42.module+el8.2.0+6024+15a2423f"},
		// 							{Comment: "libvirt is signed with Red Hat redhatrelease2 key"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Module virt-devel:rhel is enabled"},
		// 				},
		// 			},
		// 		},
		// 		Criterions: []Criterion{
		// 			{Comment: "Red Hat Enterprise Linux 8 is installed"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:            "libvirt",
		// 			Version:         "0:4.5.0-42.module+el8.2.0+6024+15a2423f",
		// 			ModularityLabel: "virt:rhel",
		// 		},
		// 		{
		// 			Name:            "libvirt",
		// 			Version:         "0:4.5.0-42.module+el8.2.0+6024+15a2423f",
		// 			ModularityLabel: "virt-devel:rhel",
		// 		},
		// 	},
		// },
		// {
		// 	version: "8",
		// 	cri: Criteria{
		// 		Criterias: []Criteria{
		// 			{
		// 				Criterias: []Criteria{
		// 					{
		// 						Criterias: []Criteria{
		// 							{
		// 								Criterias: []Criteria{
		// 									{
		// 										Criterions: []Criterion{
		// 											{Comment: "python2 is installed"},
		// 											{Comment: "python2 is signed with Red Hat redhatrelease2 key"},
		// 										},
		// 									},
		// 								},
		// 							},
		// 						},
		// 						Criterions: []Criterion{
		// 							{Comment: "Module inkscape:flatpak is enabled"},
		// 						},
		// 					},
		// 				},
		// 				Criterions: []Criterion{
		// 					{Comment: "Red Hat Enterprise Linux 8 is installed"},
		// 					{Comment: "Red Hat CoreOS 4 is installed"},
		// 				},
		// 			},
		// 		},
		// 		Criterions: []Criterion{
		// 			{Comment: "Red Hat Enterprise Linux must be installed"},
		// 		},
		// 	},
		// 	expected: []models.Package{
		// 		{
		// 			Name:            "python2",
		// 			ModularityLabel: "inkscape:flatpak",
		// 			NotFixedYet:     true,
		// 		},
		// 	},
		// },
		{
			//	{
			//		version: "6",
			//		cri: Criteria{
			//			Criterions: []Criterion{
			//				{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:    "kernel-headers",
			//				Version: "0:2.6.32-71.7.1.el6",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "6",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterions: []Criterion{
			//						{Comment: "kernel-headers is earlier than 0:2.6.32-71.7.1.el6"},
			//						{Comment: "kernel-headers is signed with Red Hat redhatrelease2 key"},
			//					},
			//				},
			//			},
			//			Criterions: []Criterion{
			//				{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
			//				{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:    "kernel-headers",
			//				Version: "0:2.6.32-71.7.1.el6",
			//			},
			//			{
			//				Name:    "kernel-kdump",
			//				Version: "0:2.6.32-71.7.1.el6",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "6",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterions: []Criterion{
			//						{Comment: "bzip2 is earlier than 0:1.0.5-7.el6_0"},
			//						{Comment: "bzip2 is signed with Red Hat redhatrelease2 key"},
			//					},
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "samba-domainjoin-gui is earlier than 0:3.5.4-68.el6_0.1"},
			//								{Comment: "samba-domainjoin-gui is signed with Red Hat redhatrelease2 key"},
			//							},
			//						},
			//					},
			//				},
			//				{
			//					Criterions: []Criterion{
			//						{Comment: "poppler-qt4 is signed with Red Hat redhatrelease2 key"},
			//						{Comment: "poppler-qt4 is earlier than 0:0.12.4-3.el6_0.1"},
			//					},
			//				},
			//			},
			//			Criterions: []Criterion{
			//				{Comment: "kernel-kdump is earlier than 0:2.6.32-71.7.1.el6"},
			//				{Comment: "kernel-kdump is signed with Red Hat redhatrelease2 key"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:    "bzip2",
			//				Version: "0:1.0.5-7.el6_0",
			//			},
			//			{
			//				Name:    "samba-domainjoin-gui",
			//				Version: "0:3.5.4-68.el6_0.1",
			//			},
			//			{
			//				Name:    "poppler-qt4",
			//				Version: "0:0.12.4-3.el6_0.1",
			//			},
			//			{
			//				Name:    "kernel-kdump",
			//				Version: "0:2.6.32-71.7.1.el6",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "6",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "rpm is earlier than 0:4.8.0-12.el6_0.2"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Red Hat Enterprise Linux 6 is installed"},
			//					},
			//				},
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "rpm is earlier than 0:4.8.0-19.el6_2.1"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Red Hat Enterprise Linux 6 is installed"},
			//					},
			//				},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:    "rpm",
			//				Version: "0:4.8.0-19.el6_2.1",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "6",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "rpm is earlier than 0:4.8.0-12.el6_0.2"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Red Hat Enterprise Linux 6 is installed"},
			//					},
			//				},
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "rpm is earlier than 0:4.8.0-19.el7_0.1"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Red Hat Enterprise Linux 7 is installed"},
			//					},
			//				},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:    "rpm",
			//				Version: "0:4.8.0-12.el6_0.2",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "8",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterions: []Criterion{
			//						{Comment: "ruby is earlier than 0:2.5.5-105.module+el8.1.0+3656+f80bfa1d"},
			//						{Comment: "ruby is signed with Red Hat redhatrelease2 key"},
			//					},
			//				},
			//			},
			//			Criterions: []Criterion{
			//				{Comment: "Red Hat Enterprise Linux 8 is installed"},
			//				{Comment: "Module ruby:2.5 is enabled"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:            "ruby",
			//				Version:         "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
			//				ModularityLabel: "ruby:2.5",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "8",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "libvirt is earlier than 0:4.5.0-42.module+el8.2.0+6024+15a2423f"},
			//								{Comment: "libvirt is signed with Red Hat redhatrelease2 key"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Module virt:rhel is enabled"},
			//					},
			//				},
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterions: []Criterion{
			//								{Comment: "libvirt is earlier than 0:4.5.0-42.module+el8.2.0+6024+15a2423f"},
			//								{Comment: "libvirt is signed with Red Hat redhatrelease2 key"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Module virt-devel:rhel is enabled"},
			//					},
			//				},
			//			},
			//			Criterions: []Criterion{
			//				{Comment: "Red Hat Enterprise Linux 8 is installed"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:            "libvirt",
			//				Version:         "0:4.5.0-42.module+el8.2.0+6024+15a2423f",
			//				ModularityLabel: "virt:rhel",
			//			},
			//			{
			//				Name:            "libvirt",
			//				Version:         "0:4.5.0-42.module+el8.2.0+6024+15a2423f",
			//				ModularityLabel: "virt-devel:rhel",
			//			},
			//		},
			//	},
			//
			//	{
			//		version: "8",
			//		cri: Criteria{
			//			Criterias: []Criteria{
			//				{
			//					Criterias: []Criteria{
			//						{
			//							Criterias: []Criteria{
			//								{
			//									Criterias: []Criteria{
			//										{
			//											Criterions: []Criterion{
			//												{Comment: "python2 is installed"},
			//												{Comment: "python2 is signed with Red Hat redhatrelease2 key"},
			//											},
			//										},
			//									},
			//								},
			//							},
			//							Criterions: []Criterion{
			//								{Comment: "Module inkscape:flatpak is enabled"},
			//							},
			//						},
			//					},
			//					Criterions: []Criterion{
			//						{Comment: "Red Hat Enterprise Linux 8 is installed"},
			//						{Comment: "Red Hat CoreOS 4 is installed"},
			//					},
			//				},
			//			},
			//			Criterions: []Criterion{
			//				{Comment: "Red Hat Enterprise Linux must be installed"},
			//			},
			//		},
			//		expected: []models.Package{
			//			{
			//				Name:            "python2",
			//				ModularityLabel: "inkscape:flatpak",
			//				NotFixedYet:     true,
			//			},
			//		},
			//	},
			version: "9",
			cri: Criteria{
				Criterias: []Criteria{
					{
						Criterions: []Criterion{
							{Comment: "ruby is earlier than 0:2.5.5-105.module+el9.1.0+3656+f80bfa1d", TestRef: "test:1"},
							{Comment: "ruby is signed with Red Hat redhatrelease2 key"},
						},
					},
				},
				Criterions: []Criterion{
					{Comment: "Red Hat Enterprise Linux 9 is installed"},
					{Comment: "Module ruby:2.5 is enabled"},
				},
			},
			expected: []models.Package{
				{
					Name:            "ruby",
					Version:         "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
					ModularityLabel: "ruby:2.5",
					Arch:            "aarch64",
				},
				{
					Name:            "ruby",
					Version:         "0:2.5.5-105.module+el8.1.0+3656+f80bfa1d",
					ModularityLabel: "ruby:2.5",
					Arch:            "x86_64",
				},
			},
			testIdx: map[string]RpminfoTest{
				"test:1": {
					Check:          "",
					Comment:        "",
					ID:             "test:1",
					Version:        "",
					CheckExistence: "",
					Object:         ObjectRef{},
					State: StateRef{
						Text:     "",
						StateRef: "state:1",
					},
				},
			},
			stateIdx: map[string]RpminfoState{
				"state:1": {
					ID:      "state:1",
					Version: "",
					Evr: struct {
						Text      string "xml:\",chardata\""
						Datatype  string "xml:\"datatype,attr\""
						Operation string "xml:\"operation,attr\""
					}{},
					SignatureKeyid: SignatureKeyid{},
					Arch: struct {
						Text      string "xml:\",chardata\""
						Datatype  string "xml:\"datatype,attr\""
						Operation string "xml:\"operation,attr\""
					}{Text: "aarch64|x86_64"},
				},
			},
		},
	}

	for i, tt := range tests {
		actual := collectRedHatPacks(tt.version, tt.cri, tt.testIdx, tt.stateIdx)
		sort.Slice(actual, func(i, j int) bool {
			if actual[i].Name == actual[j].Name {
				return actual[i].ModularityLabel < actual[j].ModularityLabel
			}
			return actual[i].Name < actual[j].Name
		})
		sort.Slice(tt.expected, func(i, j int) bool {
			if tt.expected[i].Name == tt.expected[j].Name {
				return tt.expected[i].ModularityLabel < tt.expected[j].ModularityLabel
			}
			return tt.expected[i].Name < tt.expected[j].Name
		})

		if !reflect.DeepEqual(tt.expected, actual) {
			e := pp.Sprintf("%v", tt.expected)
			a := pp.Sprintf("%v", actual)
			t.Errorf("[%d]: expected: %s\n, actual: %s\n", i, e, a)
		}
	}
}
